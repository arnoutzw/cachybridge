#include <QApplication>
#include <QAction>
#include <QDialog>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QFont>
#include <QLabel>
#include <QLocalServer>
#include <QLocalSocket>
#include <QMenu>
#include <QMessageBox>
#include <QNetworkDatagram>
#include <QPointer>
#include <QProcess>
#include <QPushButton>
#include <QSaveFile>
#include <QScreen>
#include <QSettings>
#include <QStandardPaths>
#include <QSysInfo>
#include <QTimer>
#include <QUdpSocket>
#include <QVBoxLayout>

#include <KStatusNotifierItem>

#include <algorithm>
#include <cstring>
#include <optional>

namespace {

constexpr quint16 pairingPort = 45'232;
const QByteArray pairingRequest = QByteArrayLiteral("CachyBridgePairRequest/1");
const QByteArray reconnectRequest = QByteArrayLiteral("CachyBridgeReconnect/1");

QString setupControlServerName() {
    return QStringLiteral("cachybridge-setup-control-%1")
        .arg(qEnvironmentVariable("USER", QStringLiteral("local-user")));
}

QString trayControlServerName() {
    return QStringLiteral("cachybridge-tray-control-%1")
        .arg(qEnvironmentVariable("USER", QStringLiteral("local-user")));
}

bool sendSetupCommand(const QByteArray &command) {
    QLocalSocket socket;
    socket.connectToServer(setupControlServerName());
    if (!socket.waitForConnected(300))
        return false;
    socket.write(command);
    return socket.waitForBytesWritten(300);
}

bool sendTrayCommand(const QByteArray &command) {
    QLocalSocket socket;
    socket.connectToServer(trayControlServerName());
    if (!socket.waitForConnected(300))
        return false;
    socket.write(command);
    return socket.waitForBytesWritten(300);
}

QString bundledCliPath() {
    const QString adjacent = QCoreApplication::applicationDirPath()
        + QStringLiteral("/cachybridge");
    if (QFileInfo(adjacent).isExecutable())
        return adjacent;
    return QStandardPaths::findExecutable(QStringLiteral("cachybridge"));
}

QString managedAutostartPath() {
    const QString config = QStandardPaths::writableLocation(QStandardPaths::ConfigLocation);
    return config.isEmpty() ? QString() : config + QStringLiteral("/autostart/cachybridge-tray.desktop");
}

QSettings setupSettings() {
    // Setup owns pairing and restore state under this stable application ID.
    // The tray must read the same store even though it has a different title.
    return QSettings(QStringLiteral("CachyOS"), QStringLiteral("CachyBridge Setup"));
}

QString configuredLocalName() {
    QSettings settings = setupSettings();
    const QString name = settings.value(QStringLiteral("identity/name")).toString().trimmed();
    return name.isEmpty() ? QSysInfo::machineHostName() : name;
}

bool setLoginAutostart(bool enabled) {
    const QString path = managedAutostartPath();
    if (path.isEmpty())
        return false;
    if (!enabled) {
        QFile file(path);
        if (file.open(QIODevice::ReadOnly | QIODevice::Text)
            && !QString::fromUtf8(file.readAll()).contains(QStringLiteral("X-CachyBridge-Managed=true")))
            return true;
        return !QFileInfo::exists(path) || QFile::remove(path);
    }
    if (!QDir().mkpath(QFileInfo(path).absolutePath()))
        return false;
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
        return false;
    const QByteArray desktop = QStringLiteral(
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=CachyBridge Tray\n"
        "Comment=Restore CachyBridge after login\n"
        "Exec=%1\n"
        "Icon=input-mouse\n"
        "Terminal=false\n"
        "X-KDE-autostart-after=panel\n"
        "X-CachyBridge-Managed=true\n")
        .arg(QCoreApplication::applicationFilePath()).toUtf8();
    if (file.write(desktop) != desktop.size())
        return false;
    file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    return file.commit();
}

class CachyBridgeTray final : public QObject {
public:
    explicit CachyBridgeTray(QApplication &application)
        : application_(application), item_(QStringLiteral("cachybridge"), this) {
        item_.setCategory(KStatusNotifierItem::ApplicationStatus);
        item_.setStatus(KStatusNotifierItem::Active);
        item_.setTitle(QStringLiteral("CachyBridge"));
        item_.setIconByName(QStringLiteral("input-mouse"));
        item_.setToolTipTitle(QStringLiteral("CachyBridge"));
        item_.setToolTipSubTitle(QStringLiteral("Double-click to open setup"));
        // KDE supplies the native Quit/Afsluiten action for the status item.
        // Make that single action also close Setup and stop every session.
        connect(&application_, &QCoreApplication::aboutToQuit, this, [this] {
            sendSetupCommand("quit");
            stopPairingAvailability();
            stopSharing();
        });

        auto *menu = new QMenu;
        menu->addAction(QStringLiteral("Open CachyBridge setup"), this,
            [this] { openSetup(); });
        menu->addAction(QStringLiteral("Reconnect saved pairing now"), this,
            [this] { restoreSavedSession(); });
        auto *startAtLogin = menu->addAction(QStringLiteral("Start and reconnect at login"));
        startAtLogin->setCheckable(true);
        QSettings settings = setupSettings();
        startAtLogin->setChecked(settings.value(QStringLiteral("startup/enabled"), false).toBool());
        connect(startAtLogin, &QAction::toggled, this, [this, startAtLogin](bool enabled) {
            if (!setLoginAutostart(enabled)) {
                startAtLogin->setChecked(false);
                return;
            }
            QSettings settings = setupSettings();
            settings.setValue(QStringLiteral("startup/enabled"), enabled);
            settings.sync();
        });
        item_.setContextMenu(menu);

        connect(&item_, &KStatusNotifierItem::activateRequested, this,
            [this](bool active, const QPoint &) {
                if (!active)
                    return;
                if (lastActivation_.isValid()
                    && lastActivation_.elapsed() <= QApplication::doubleClickInterval()) {
                    lastActivation_.invalidate();
                    openSetup();
                } else {
                    lastActivation_.start();
                }
            });

        enableClientPairingDiscovery();

        if (settings.value(QStringLiteral("startup/enabled"), false).toBool()) {
            QTimer::singleShot(3000, this, [this] { restoreSavedSession(); });
        }
    }

    void refreshIdentity() {
        if (!pairingRequests_)
            return;
        if (pairingAdvertiser_ && pairingAdvertiser_->state() != QProcess::NotRunning) {
            pairingAdvertiser_->terminate();
            if (!pairingAdvertiser_->waitForFinished(500))
                pairingAdvertiser_->kill();
        }
        if (pairingAdvertiser_) {
            pairingAdvertiser_->deleteLater();
            pairingAdvertiser_ = nullptr;
        }
        startPairingAdvertisement();
    }

private:
    static QString pairedPeerIdFromOutput(const QByteArray &output) {
        for (const QByteArray &line : output.split('\n')) {
            static constexpr auto prefix = "paired_peer_id=";
            if (!line.startsWith(prefix))
                continue;
            const QString peerId = QString::fromUtf8(line.sliced(int(strlen(prefix)))).trimmed();
            if (peerId.size() == 32)
                return peerId;
        }
        return {};
    }

    void enableClientPairingDiscovery() {
        QSettings settings = setupSettings();
        const QString configuredRole = settings.value(QStringLiteral("startup/role")).toString();
        const QString cli = bundledCliPath();
        // A saved topology is authoritative: a host may retain an older UI
        // role preference, but it must never occupy the client discovery port.
        const std::optional<bool> peerRole = configuredClientRole(cli);
        if (peerRole ? !*peerRole : configuredRole != QStringLiteral("client"))
            return;
        if (cli.isEmpty())
            return;
        pairingRequests_ = new QUdpSocket(this);
        if (!pairingRequests_->bind(QHostAddress::AnyIPv4, pairingPort,
                                    QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint)) {
            pairingRequests_->deleteLater();
            pairingRequests_ = nullptr;
            return;
        }
        connect(pairingRequests_, &QUdpSocket::readyRead, this, [this] { readPairingRequests(); });
        startPairingAdvertisement();
    }

    void startPairingAdvertisement() {
        const QString cli = bundledCliPath();
        if (!pairingRequests_ || cli.isEmpty())
            return;
        pairingAdvertiser_ = new QProcess(this);
        pairingAdvertiser_->start(cli, {QStringLiteral("pair-advertise"),
            QStringLiteral("--local-name"), configuredLocalName(),
            QStringLiteral("--pairing-port"), QString::number(pairingPort)});
    }

    static std::optional<bool> configuredClientRole(const QString &cli) {
        if (cli.isEmpty())
            return std::nullopt;
        QProcess process;
        process.start(cli, {QStringLiteral("peer-list")});
        if (!process.waitForStarted() || !process.waitForFinished(2000)
            || process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
            return std::nullopt;
        }
        const QStringList peers = QString::fromUtf8(process.readAllStandardOutput())
            .split(u'\n', Qt::SkipEmptyParts);
        if (peers.isEmpty())
            return std::nullopt;
        return std::any_of(peers.cbegin(), peers.cend(), [](const QString &peer) {
            return peer.section(u'\t', 2, 2) == QStringLiteral("right");
        });
    }

    void stopPairingAvailability() {
        if (pairingRequests_) {
            pairingRequests_->close();
            pairingRequests_ = nullptr;
        }
        if (pairingAdvertiser_ && pairingAdvertiser_->state() != QProcess::NotRunning) {
            pairingAdvertiser_->terminate();
            if (!pairingAdvertiser_->waitForFinished(500))
                pairingAdvertiser_->kill();
        }
        if (pairingProcess_ && pairingProcess_->state() != QProcess::NotRunning)
            pairingProcess_->kill();
    }

    void readPairingRequests() {
        while (pairingRequests_ && pairingRequests_->hasPendingDatagrams()) {
            const QNetworkDatagram request = pairingRequests_->receiveDatagram();
            if (request.data().trimmed() == pairingRequest)
                showClientPairingCode();
            else if (request.data().trimmed() == reconnectRequest)
                restoreSavedSession();
        }
    }

    void showClientPairingCode() {
        if (pairingProcess_) {
            if (pairingDialog_) {
                pairingDialog_->showNormal();
                pairingDialog_->raise();
                pairingDialog_->activateWindow();
            }
            return;
        }
        const QString cli = bundledCliPath();
        QProcess generator;
        generator.start(cli, {QStringLiteral("pair-code")});
        if (!generator.waitForStarted() || !generator.waitForFinished(5'000)
            || generator.exitStatus() != QProcess::NormalExit || generator.exitCode() != 0) {
            QMessageBox::warning(nullptr, QStringLiteral("Could not start pairing"),
                QStringLiteral("CachyBridge could not create a one-time pairing code."));
            return;
        }
        const QString code = QString::fromUtf8(generator.readAllStandardOutput()).trimmed();
        if (code.size() != 5)
            return;

        pairingDialog_ = new QDialog;
        pairingDialog_->setAttribute(Qt::WA_DeleteOnClose);
        pairingDialog_->setWindowTitle(QStringLiteral("CachyBridge pairing code"));
        pairingDialog_->setMinimumWidth(520);
        auto *layout = new QVBoxLayout(pairingDialog_);
        auto *heading = new QLabel(QStringLiteral("Enter this code on the host iMac"));
        heading->setAlignment(Qt::AlignCenter);
        auto *codeLabel = new QLabel(code);
        QFont codeFont = codeLabel->font();
        codeFont.setPointSize(std::max(codeFont.pointSize() + 30, 48));
        codeFont.setBold(true);
        codeLabel->setFont(codeFont);
        codeLabel->setAlignment(Qt::AlignCenter);
        codeLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        auto *hint = new QLabel(QStringLiteral(
            "This one-time code expires in five minutes. Keep this tray open while pairing."));
        hint->setWordWrap(true);
        hint->setAlignment(Qt::AlignCenter);
        auto *cancel = new QPushButton(QStringLiteral("Cancel pairing"));
        layout->addWidget(heading);
        layout->addWidget(codeLabel);
        layout->addWidget(hint);
        layout->addWidget(cancel);
        connect(cancel, &QPushButton::clicked, pairingDialog_, &QDialog::reject);
        connect(pairingDialog_, &QDialog::finished, this, [this](int) {
            if (pairingProcess_ && pairingProcess_->state() != QProcess::NotRunning)
                pairingProcess_->kill();
            pairingDialog_ = nullptr;
        });
        pairingDialog_->show();
        pairingDialog_->raise();
        pairingDialog_->activateWindow();

        const QString systemctl = QStandardPaths::findExecutable(QStringLiteral("systemctl"));
        if (!systemctl.isEmpty()) {
            QProcess::execute(systemctl, {QStringLiteral("--user"), QStringLiteral("stop"),
                QStringLiteral("cachybridge-seamless-client")});
        }
        pairingProcess_ = new QProcess(this);
        pairingProcess_->start(cli, {QStringLiteral("pair-client"),
            QStringLiteral("--listen"), QStringLiteral("0.0.0.0:45232"),
            QStringLiteral("--code"), code,
            QStringLiteral("--local-name"), configuredLocalName(),
            QStringLiteral("--persistent-permissions")});
        if (!pairingProcess_->waitForStarted()) {
            pairingDialog_->reject();
            pairingProcess_->deleteLater();
            pairingProcess_ = nullptr;
            QMessageBox::warning(nullptr, QStringLiteral("Could not start pairing"),
                QStringLiteral("CachyBridge could not open the client pairing listener."));
            return;
        }
        QProcess *process = pairingProcess_;
        connect(process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
            [this, process](int exitCode, QProcess::ExitStatus status) {
                const QString peerId = pairedPeerIdFromOutput(process->readAllStandardOutput());
                const QString details = QString::fromUtf8(process->readAllStandardError()).trimmed();
                if (pairingProcess_ == process)
                    pairingProcess_ = nullptr;
                process->deleteLater();
                if (pairingDialog_)
                    pairingDialog_->accept();
                if (status != QProcess::NormalExit || exitCode != 0 || peerId.isEmpty()) {
                    if (!details.isEmpty())
                        QMessageBox::warning(nullptr, QStringLiteral("Pairing did not complete"), details);
                    return;
                }
                QSettings settings = setupSettings();
                const auto *screen = QGuiApplication::primaryScreen();
                const QSize local = screen ? screen->size() : QSize(2560, 1440);
                settings.setValue(QStringLiteral("startup/peer-id"), peerId);
                settings.setValue(QStringLiteral("startup/role"), QStringLiteral("client"));
                settings.setValue(QStringLiteral("startup/peer-width"), local.width());
                settings.setValue(QStringLiteral("startup/peer-height"), local.height());
                settings.sync();
                QTimer::singleShot(250, this, [this] { restoreSavedSession(); });
            });
    }

    void stopSharing() const {
        const QString systemctl = QStandardPaths::findExecutable(QStringLiteral("systemctl"));
        if (systemctl.isEmpty())
            return;
        // Only one role is normally active, but stopping both makes Quit
        // reliable after a role change or an interrupted re-pair.
        QProcess::execute(systemctl, {QStringLiteral("--user"), QStringLiteral("stop"),
            QStringLiteral("cachybridge-seamless-host"),
            QStringLiteral("cachybridge-seamless-client")});
    }

    void openSetup() {
        if (sendSetupCommand("activate"))
            return;
        const QString adjacent = QCoreApplication::applicationDirPath()
            + QStringLiteral("/cachybridge-setup");
        const QString program = QFileInfo(adjacent).isExecutable()
            ? adjacent : QStandardPaths::findExecutable(QStringLiteral("cachybridge-setup"));
        if (!program.isEmpty())
            QProcess::startDetached(program, {});
    }

    void restoreSavedSession() {
        QSettings settings = setupSettings();
        const QString peerId = settings.value(QStringLiteral("startup/peer-id")).toString();
        const QString role = settings.value(QStringLiteral("startup/role")).toString();
        if (peerId.size() != 32 || (role != QStringLiteral("host") && role != QStringLiteral("client"))) {
            openSetup();
            return;
        }
        const auto *screen = QGuiApplication::primaryScreen();
        const QSize local = screen ? screen->size() : QSize(2560, 1440);
        const int peerWidth = settings.value(QStringLiteral("startup/peer-width"), local.width()).toInt();
        const int peerHeight = settings.value(QStringLiteral("startup/peer-height"), local.height()).toInt();
        const QString cli = bundledCliPath();
        const QString systemdRun = QStandardPaths::findExecutable(QStringLiteral("systemd-run"));
        const QString systemctl = QStandardPaths::findExecutable(QStringLiteral("systemctl"));
        if (cli.isEmpty() || systemdRun.isEmpty() || systemctl.isEmpty())
            return;
        const bool host = role == QStringLiteral("host");
        const QString unit = host ? QStringLiteral("cachybridge-seamless-host")
                                  : QStringLiteral("cachybridge-seamless-client");
        QProcess::execute(systemctl, {QStringLiteral("--user"), QStringLiteral("stop"), unit});
        QStringList arguments{
            QStringLiteral("--user"),
            QStringLiteral("--unit=") + unit,
            QStringLiteral("--collect"),
            // A failed connection or a dismissed portal request must not
            // repeatedly reopen the InputCapture consent dialog. The tray
            // tries once at login; Connect in Setup is the intentional retry.
            QStringLiteral("--property=Restart=no"),
        };
        for (const QString &name : {QStringLiteral("XDG_RUNTIME_DIR"),
                                    QStringLiteral("DBUS_SESSION_BUS_ADDRESS"),
                                    QStringLiteral("XDG_SESSION_TYPE"),
                                    QStringLiteral("WAYLAND_DISPLAY")}) {
            const QString value = qEnvironmentVariable(name.toUtf8().constData());
            if (!value.isEmpty())
                arguments << QStringLiteral("--setenv=") + name + u'=' + value;
        }
        arguments << cli;
        if (host) {
            arguments << QStringLiteral("seamless-host-config") << QStringLiteral("--peer") << peerId
                << QStringLiteral("--local-width") << QString::number(local.width())
                << QStringLiteral("--local-height") << QString::number(local.height())
                << QStringLiteral("--peer-width") << QString::number(peerWidth)
                << QStringLiteral("--peer-height") << QString::number(peerHeight)
                << QStringLiteral("--peer-y") << QStringLiteral("0");
        } else {
            arguments << QStringLiteral("seamless-client-config") << QStringLiteral("--peer") << peerId
                << QStringLiteral("--peer-width") << QString::number(local.width())
                << QStringLiteral("--peer-y") << QStringLiteral("0");
        }
        QProcess::startDetached(systemdRun, arguments);
    }

    QApplication &application_;
    KStatusNotifierItem item_;
    QElapsedTimer lastActivation_;
    QUdpSocket *pairingRequests_ = nullptr;
    QProcess *pairingAdvertiser_ = nullptr;
    QProcess *pairingProcess_ = nullptr;
    QPointer<QDialog> pairingDialog_;
};

} // namespace

int main(int argc, char **argv) {
    QApplication application(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("CachyBridge"));
    QCoreApplication::setOrganizationName(QStringLiteral("CachyOS"));
    application.setQuitOnLastWindowClosed(false);

    // Setup may start this utility on demand. Keep exactly one notifier icon
    // and one UDP pairing responder per desktop session.
    if (sendTrayCommand("ping"))
        return 0;
    QLocalServer::removeServer(trayControlServerName());
    QLocalServer trayControl;
    if (!trayControl.listen(trayControlServerName()))
        return 1;
    CachyBridgeTray tray(application);
    QObject::connect(&trayControl, &QLocalServer::newConnection, &application, [&trayControl, &tray] {
        while (QLocalSocket *socket = trayControl.nextPendingConnection()) {
            const auto reply = [socket, &tray] {
                const QByteArray command = socket->readAll().trimmed();
                if (command == "refresh-identity")
                    tray.refreshIdentity();
                socket->write("ok");
                socket->disconnectFromServer();
                socket->deleteLater();
            };
            QObject::connect(socket, &QLocalSocket::readyRead, socket, reply);
            if (socket->bytesAvailable() > 0)
                reply();
        }
    });
    return application.exec();
}
