#include <QApplication>
#include <QAction>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QLocalSocket>
#include <QMenu>
#include <QProcess>
#include <QSaveFile>
#include <QScreen>
#include <QSettings>
#include <QStandardPaths>
#include <QTimer>

#include <KStatusNotifierItem>

namespace {

QString setupControlServerName() {
    return QStringLiteral("cachybridge-setup-control-%1")
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

        auto *menu = new QMenu;
        menu->addAction(QStringLiteral("Open CachyBridge setup"), this,
            [this] { openSetup(); });
        menu->addAction(QStringLiteral("Reconnect saved pairing now"), this,
            [this] { restoreSavedSession(); });
        auto *startAtLogin = menu->addAction(QStringLiteral("Start and reconnect at login"));
        startAtLogin->setCheckable(true);
        QSettings settings;
        startAtLogin->setChecked(settings.value(QStringLiteral("startup/enabled"), false).toBool());
        connect(startAtLogin, &QAction::toggled, this, [this, startAtLogin](bool enabled) {
            if (!setLoginAutostart(enabled)) {
                startAtLogin->setChecked(false);
                return;
            }
            QSettings settings;
            settings.setValue(QStringLiteral("startup/enabled"), enabled);
            settings.sync();
        });
        menu->addSeparator();
        menu->addAction(QStringLiteral("Quit CachyBridge"), this, [this] {
            // The setup window may have been opened from the Start Menu, not
            // by this tray process. Use the local control socket so Quit is a
            // single, predictable action in either case.
            sendSetupCommand("quit");
            application_.quit();
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

        if (settings.value(QStringLiteral("startup/enabled"), false).toBool()) {
            QTimer::singleShot(3000, this, [this] { restoreSavedSession(); });
        }
    }

private:
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
        QSettings settings;
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
            QStringLiteral("--property=Restart=") + (host
                ? QStringLiteral("on-failure") : QStringLiteral("on-failure")),
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
};

} // namespace

int main(int argc, char **argv) {
    QApplication application(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("CachyBridge"));
    QCoreApplication::setOrganizationName(QStringLiteral("CachyOS"));
    application.setQuitOnLastWindowClosed(false);
    CachyBridgeTray tray(application);
    return application.exec();
}
