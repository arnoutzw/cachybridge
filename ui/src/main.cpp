#include <QApplication>
#include <QCheckBox>
#include <QCommandLineParser>
#include <QDateTime>
#include <QDialog>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFormLayout>
#include <QGraphicsRectItem>
#include <QGraphicsScene>
#include <QGraphicsSceneMouseEvent>
#include <QGraphicsSimpleTextItem>
#include <QGraphicsView>
#include <QGuiApplication>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QLocalServer>
#include <QLocalSocket>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QSaveFile>
#include <QScreen>
#include <QSpinBox>
#include <QSysInfo>
#include <QStandardPaths>
#include <QTemporaryFile>
#include <QTemporaryDir>
#include <QTabWidget>
#include <QTextStream>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <functional>
#include <memory>

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

enum class Placement { Left, Right, Above, Below };
enum class MachineRole { Host, Client };

QString placementName(Placement placement) {
    switch (placement) {
    case Placement::Left: return QStringLiteral("left");
    case Placement::Right: return QStringLiteral("right");
    case Placement::Above: return QStringLiteral("above");
    case Placement::Below: return QStringLiteral("below");
    }
    return QStringLiteral("left");
}

void logSetupDiagnostic(const QString &event, const QString &details) {
    const QString directory = QStandardPaths::writableLocation(
        QStandardPaths::AppLocalDataLocation);
    if (directory.isEmpty() || !QDir().mkpath(directory))
        return;
    QFile file(directory + QStringLiteral("/setup.log"));
    if (!file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text))
        return;
    file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    QTextStream(&file) << QDateTime::currentDateTime().toString(Qt::ISODateWithMs)
                       << ' ' << event << ": " << details << '\n';
}

QString bundledCliPath() {
    const QString adjacent = QCoreApplication::applicationDirPath()
        + QStringLiteral("/cachybridge");
    if (QFileInfo(adjacent).isExecutable())
        return adjacent;
    const QString discovered = QStandardPaths::findExecutable(QStringLiteral("cachybridge"));
    if (!discovered.isEmpty())
        return discovered;
    return adjacent;
}

QString clipboardToolPath(const QString &name) {
    const QString bundled = QCoreApplication::applicationDirPath() + u'/' + name;
    if (QFileInfo(bundled).isExecutable())
        return bundled;
    return QStandardPaths::findExecutable(name);
}

bool clipboardToolsAvailable() {
    return !clipboardToolPath(QStringLiteral("wl-copy")).isEmpty()
        && !clipboardToolPath(QStringLiteral("wl-paste")).isEmpty();
}

struct SetupDraft {
    QString hostName;
    QString hostEndpoint;
    QString clientName;
    QString clientEndpoint;
    QString pairingPsk;
    Placement placement = Placement::Left;
    bool persistentPermissions = false;
};

struct PairJoinDraft {
    QString localName;
    QString clientAddress;
    QString code;
    Placement placement = Placement::Left;
    bool persistentPermissions = false;
};

bool isPeerId(const QString &value) {
    return value.size() == 32 && std::all_of(value.cbegin(), value.cend(), [](QChar character) {
        return character.isDigit()
            || (character >= u'a' && character <= u'f')
            || (character >= u'A' && character <= u'F');
    });
}

QString pairedPeerIdFromOutput(const QString &output) {
    for (const QString &line : output.split(u'\n', Qt::SkipEmptyParts)) {
        constexpr auto prefix = "paired_peer_id=";
        if (line.startsWith(QLatin1String(prefix))) {
            const QString id = line.sliced(int(std::char_traits<char>::length(prefix))).trimmed();
            if (isPeerId(id))
                return id;
        }
    }
    return {};
}

QString detectedLanCidr() {
    QProcess process;
    process.start(QStringLiteral("ip"), {
        QStringLiteral("-o"), QStringLiteral("-4"), QStringLiteral("addr"),
        QStringLiteral("show"), QStringLiteral("scope"), QStringLiteral("global")
    });
    if (!process.waitForStarted() || !process.waitForFinished(1000)
        || process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0)
        return {};
    for (const QString &line : QString::fromUtf8(process.readAllStandardOutput())
             .split(u'\n', Qt::SkipEmptyParts)) {
        const QStringList fields = line.simplified().split(u' ', Qt::SkipEmptyParts);
        const int inet = fields.indexOf(QStringLiteral("inet"));
        if (inet < 0 || inet + 1 >= fields.size()) continue;
        const QStringList address = fields.at(inet + 1).split(u'/');
        bool prefixOk = false;
        const int prefix = address.value(1).toInt(&prefixOk);
        const QStringList octets = address.value(0).split(u'.');
        if (!prefixOk || prefix < 8 || prefix > 30 || octets.size() != 4) continue;
        quint32 raw = 0;
        bool valid = true;
        for (const QString &octet : octets) {
            bool ok = false;
            const auto value = octet.toUInt(&ok);
            if (!ok || value > 255) { valid = false; break; }
            raw = (raw << 8) | value;
        }
        if (!valid) continue;
        const quint32 mask = 0xffffffffu << (32 - prefix);
        const quint32 network = raw & mask;
        return QStringLiteral("%1.%2.%3.%4/%5")
            .arg((network >> 24) & 255).arg((network >> 16) & 255)
            .arg((network >> 8) & 255).arg(network & 255).arg(prefix);
    }
    return {};
}

QString firewallPermissionMarkerPath() {
    const QString directory = QStandardPaths::writableLocation(
        QStandardPaths::AppLocalDataLocation);
    return directory.isEmpty() ? QString() : directory + QStringLiteral("/firewall-v2-ready");
}

bool firewallPermissionConfigured() {
    const QString marker = firewallPermissionMarkerPath();
    return !marker.isEmpty() && QFileInfo::exists(marker);
}

bool rememberFirewallPermission() {
    const QString marker = firewallPermissionMarkerPath();
    if (marker.isEmpty() || !QDir().mkpath(QFileInfo(marker).absolutePath()))
        return false;
    QSaveFile file(marker);
    if (!file.open(QIODevice::WriteOnly) || file.write("ports=45231:45234\n") < 0)
        return false;
    file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    return file.commit();
}

class DraggableClientTile final : public QGraphicsRectItem {
public:
    explicit DraggableClientTile(const QRectF &rect, std::function<void(QPointF)> released)
        : QGraphicsRectItem(rect), released_(std::move(released)) {
        setFlags(ItemIsMovable | ItemSendsGeometryChanges);
        setCursor(Qt::OpenHandCursor);
    }

protected:
    void mousePressEvent(QGraphicsSceneMouseEvent *event) override {
        setCursor(Qt::ClosedHandCursor);
        QGraphicsRectItem::mousePressEvent(event);
    }

    void mouseReleaseEvent(QGraphicsSceneMouseEvent *event) override {
        QGraphicsRectItem::mouseReleaseEvent(event);
        setCursor(Qt::OpenHandCursor);
        released_(pos());
    }

private:
    std::function<void(QPointF)> released_;
};

class DisplayLayoutPreview final : public QGraphicsView {
public:
    DisplayLayoutPreview() : scene_(this) {
        setScene(&scene_);
        setMinimumHeight(260);
        setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        setFrameShape(QFrame::NoFrame);
        const auto *screen = QGuiApplication::primaryScreen();
        hostResolution_ = screen ? screen->size() : QSize(2560, 1440);
        clientResolution_ = hostResolution_;
        rebuild();
    }

    Placement placement() const { return placement_; }

    QSize clientResolution() const { return clientResolution_; }

    void setClientResolution(QSize resolution) {
        clientResolution_.setWidth(std::max(resolution.width(), 640));
        clientResolution_.setHeight(std::max(resolution.height(), 480));
        rebuild();
    }

private:
    void resizeEvent(QResizeEvent *event) override {
        QGraphicsView::resizeEvent(event);
        fitInView(scene_.sceneRect(), Qt::KeepAspectRatio);
    }

    void rebuild() {
        scene_.clear();
        const qreal scale = std::min(280.0 / hostResolution_.width(), 165.0 / hostResolution_.height());
        const QSizeF host(hostResolution_.width() * scale, hostResolution_.height() * scale);
        const QSizeF client(clientResolution_.width() * scale, clientResolution_.height() * scale);
        const QRectF hostRect(0, 0, host.width(), host.height());
        auto *hostTile = scene_.addRect(hostRect, QPen(palette().highlight(), 2), QBrush(palette().base()));
        auto *hostLabel = scene_.addSimpleText(
            QStringLiteral("Host\n%1 × %2").arg(hostResolution_.width()).arg(hostResolution_.height()));
        hostLabel->setPos(hostRect.center() - hostLabel->boundingRect().center());
        hostLabel->setParentItem(hostTile);

        QRectF clientRect(0, 0, client.width(), client.height());
        clientTile_ = new DraggableClientTile(clientRect, [this](QPointF point) { snapFrom(point); });
        clientTile_->setPen(QPen(palette().highlight(), 2));
        clientTile_->setBrush(QBrush(palette().alternateBase()));
        scene_.addItem(clientTile_);
        auto *clientLabel = scene_.addSimpleText(
            QStringLiteral("Client\n%1 × %2").arg(clientResolution_.width()).arg(clientResolution_.height()));
        clientLabel->setPos(clientRect.center() - clientLabel->boundingRect().center());
        clientLabel->setParentItem(clientTile_);

        placeClient(hostRect, clientRect);
        hostRect_ = hostRect;
        scene_.setSceneRect(-client.width() - 40, -client.height() - 40,
            host.width() + client.width() * 2 + 80, host.height() + client.height() * 2 + 80);
        fitInView(scene_.sceneRect(), Qt::KeepAspectRatio);
    }

    void placeClient(const QRectF &host, const QRectF &client) {
        constexpr qreal gap = 14;
        QPointF position;
        switch (placement_) {
        case Placement::Left: position = {host.left() - client.width() - gap, host.center().y() - client.height() / 2}; break;
        case Placement::Right: position = {host.right() + gap, host.center().y() - client.height() / 2}; break;
        case Placement::Above: position = {host.center().x() - client.width() / 2, host.top() - client.height() - gap}; break;
        case Placement::Below: position = {host.center().x() - client.width() / 2, host.bottom() + gap}; break;
        }
        clientTile_->setPos(position);
    }

    void snapFrom(QPointF position) {
        const QPointF hostCenter = hostRect_.center();
        const QPointF clientCenter = position + clientTile_->rect().center();
        const QPointF delta = clientCenter - hostCenter;
        // Current portal capture supports horizontal barriers.  A vertical
        // drop intentionally resolves to a usable left/right placement.
        placement_ = delta.x() < 0 ? Placement::Left : Placement::Right;
        rebuild();
    }

    QGraphicsScene scene_;
    DraggableClientTile *clientTile_ = nullptr;
    QSize hostResolution_;
    QSize clientResolution_;
    QRectF hostRect_;
    Placement placement_ = Placement::Left;
};

class RoleSelectionDialog final : public QDialog {
public:
    RoleSelectionDialog() {
        setWindowTitle(QStringLiteral("CachyBridge — choose this iMac's role"));
        setModal(true);
        setMinimumWidth(480);
        auto *heading = new QLabel(QStringLiteral("What role should this iMac have?"));
        QFont headingFont = heading->font();
        headingFont.setPointSize(headingFont.pointSize() + 4);
        headingFont.setBold(true);
        heading->setFont(headingFont);
        auto *host = new QPushButton(QStringLiteral("Host / master\nOwns the physical mouse and keyboard"));
        auto *client = new QPushButton(QStringLiteral("Client / slave\nReceives shared input from the host"));
        for (auto *button : {host, client}) {
            button->setMinimumHeight(76);
            button->setStyleSheet(QStringLiteral("QPushButton { text-align: left; padding: 12px; }"));
        }
        connect(host, &QPushButton::clicked, this, [this] { role_ = MachineRole::Host; accept(); });
        connect(client, &QPushButton::clicked, this, [this] { role_ = MachineRole::Client; accept(); });
        auto *layout = new QVBoxLayout(this);
        layout->addWidget(heading);
        layout->addWidget(new QLabel(QStringLiteral(
            "The host connects to the client during pairing and when sharing input.")));
        layout->addWidget(host);
        layout->addWidget(client);
    }

    MachineRole role() const { return role_; }

private:
    MachineRole role_ = MachineRole::Host;
};

class SetupStore {
public:
    virtual ~SetupStore() = default;
    virtual QString generatePairingToken(QString *error) = 0;
    virtual QString generatePairingCode(QString *error) = 0;
    virtual QString startPairClient(const SetupDraft &draft, const QString &code,
                                    QProcess *process) = 0;
    virtual QString connectPairHost(const PairJoinDraft &draft, QString *peerId) = 0;
    virtual QStringList discoverPairClients(QString *error) = 0;
    virtual QStringList configuredPeers(QString *error) = 0;
    virtual QString applyTopology(const QString &peerId, Placement placement) = 0;
    virtual QString ensureClientFirewall() = 0;
    virtual QString save(const SetupDraft &draft) = 0;
};

class CliSetupStore final : public SetupStore {
public:
    CliSetupStore(QString cachybridge, QString configPath)
        : cachybridge_(std::move(cachybridge)), configPath_(std::move(configPath)) {}

    QString generatePairingToken(QString *error) override {
        QTemporaryDir directory;
        if (!directory.isValid()) {
            *error = QStringLiteral("Could not create a private temporary directory.");
            return {};
        }
        const QString path = directory.filePath(QStringLiteral("pairing.token"));
        QProcess process;
        process.start(cachybridge_, {
            QStringLiteral("pair-token"), QStringLiteral("--output"), path
        });
        if (!process.waitForStarted() || !process.waitForFinished(15000)
            || process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
            const auto details = QString::fromUtf8(process.readAllStandardError()).trimmed();
            *error = details.isEmpty()
                ? QStringLiteral("The secure pairing-token generator failed.") : details;
            return {};
        }
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly)) {
            *error = QStringLiteral("Could not read the generated private token.");
            return {};
        }
        const QString token = QString::fromUtf8(file.readAll()).trimmed();
        if (token.size() != 64) {
            *error = QStringLiteral("The token generator returned an unexpected value.");
            return {};
        }
        return token;
    }

    QString generatePairingCode(QString *error) override {
        QProcess process;
        process.start(cachybridge_, {QStringLiteral("pair-code")});
        const bool started = process.waitForStarted();
        const bool finished = started && process.waitForFinished(15000);
        if (!started || !finished
            || process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
            const auto details = QString::fromUtf8(process.readAllStandardError()).trimmed();
            const QString reason = details.isEmpty() ? process.errorString() : details;
            logSetupDiagnostic(QStringLiteral("pair-code failed"),
                QStringLiteral("program=%1 started=%2 finished=%3 status=%4 exit=%5 reason=%6")
                    .arg(cachybridge_)
                    .arg(started)
                    .arg(finished)
                    .arg(static_cast<int>(process.exitStatus()))
                    .arg(process.exitCode())
                    .arg(reason));
            *error = QStringLiteral("Could not start the CachyBridge code generator at %1: %2")
                .arg(cachybridge_, reason);
            return {};
        }
        const QString code = QString::fromUtf8(process.readAllStandardOutput()).trimmed();
        if (code.size() != 5) {
            logSetupDiagnostic(QStringLiteral("pair-code invalid output"),
                QStringLiteral("program=%1 length=%2").arg(cachybridge_).arg(code.size()));
            *error = QStringLiteral("The code generator returned an unexpected value.");
            return {};
        }
        logSetupDiagnostic(QStringLiteral("pair-code succeeded"),
            QStringLiteral("program=%1").arg(cachybridge_));
        return code;
    }

    QString startPairClient(const SetupDraft &draft, const QString &code,
                            QProcess *process) override {
        QStringList arguments{
            QStringLiteral("pair-client"), QStringLiteral("--listen"),
            QStringLiteral("0.0.0.0:45232"), QStringLiteral("--code"), code,
            QStringLiteral("--local-name"), draft.hostName,
        };
        if (!configPath_.isEmpty())
            arguments << QStringLiteral("--config") << configPath_;
        if (draft.persistentPermissions)
            arguments << QStringLiteral("--persistent-permissions");
        process->start(cachybridge_, arguments);
        if (!process->waitForStarted())
            return QStringLiteral("Could not start %1: %2").arg(cachybridge_, process->errorString());
        return {};
    }

    QString connectPairHost(const PairJoinDraft &draft, QString *peerId) override {
        QProcess process;
        QStringList arguments{
            QStringLiteral("pair-host"), QStringLiteral("--connect"), draft.clientAddress,
            QStringLiteral("--code"), draft.code, QStringLiteral("--local-name"), draft.localName,
            QStringLiteral("--placement"), placementName(draft.placement),
        };
        if (!configPath_.isEmpty())
            arguments << QStringLiteral("--config") << configPath_;
        if (draft.persistentPermissions)
            arguments << QStringLiteral("--persistent-permissions");
        process.start(cachybridge_, arguments);
        if (!process.waitForStarted())
            return QStringLiteral("Could not start %1: %2").arg(cachybridge_, process.errorString());
        if (!process.waitForFinished(30000)) {
            process.kill();
            return QStringLiteral("Pairing timed out. Check the client address, code, and LAN firewall.");
        }
        if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
            const auto details = QString::fromUtf8(process.readAllStandardError()).trimmed();
            return details.isEmpty() ? QStringLiteral("Pairing was rejected or expired.") : details;
        }
        *peerId = pairedPeerIdFromOutput(QString::fromUtf8(process.readAllStandardOutput()));
        if (peerId->isEmpty()) {
            logSetupDiagnostic(QStringLiteral("pair-host missing peer id"),
                QStringLiteral("program=%1").arg(cachybridge_));
            return QStringLiteral("Pairing completed but did not return a usable peer ID.");
        }
        return {};
    }

    QStringList discoverPairClients(QString *error) override {
        QProcess process;
        process.start(cachybridge_, {QStringLiteral("pair-discover"), QStringLiteral("--timeout-seconds"), QStringLiteral("2")});
        if (!process.waitForStarted() || !process.waitForFinished(4000)
            || process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
            const auto details = QString::fromUtf8(process.readAllStandardError()).trimmed();
            *error = details.isEmpty() ? QStringLiteral("Client discovery failed.") : details;
            return {};
        }
        return QString::fromUtf8(process.readAllStandardOutput())
            .split(u'\n', Qt::SkipEmptyParts);
    }

    QStringList configuredPeers(QString *error) override {
        QProcess process;
        QStringList arguments{QStringLiteral("peer-list")};
        if (!configPath_.isEmpty()) arguments << QStringLiteral("--config") << configPath_;
        process.start(cachybridge_, arguments);
        if (!process.waitForStarted() || !process.waitForFinished(5000)
            || process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
            const QString details = QString::fromUtf8(process.readAllStandardError()).trimmed();
            *error = details.isEmpty() ? QStringLiteral("Could not read saved pairings.") : details;
            return {};
        }
        return QString::fromUtf8(process.readAllStandardOutput())
            .split(u'\n', Qt::SkipEmptyParts);
    }

    QString applyTopology(const QString &peerId, Placement placement) override {
        QProcess process;
        QStringList arguments{QStringLiteral("topology-apply"), QStringLiteral("--peer"), peerId,
            QStringLiteral("--placement"), placementName(placement)};
        if (!configPath_.isEmpty()) arguments << QStringLiteral("--config") << configPath_;
        process.start(cachybridge_, arguments);
        if (!process.waitForStarted())
            return QStringLiteral("Could not start %1: %2").arg(cachybridge_, process.errorString());
        if (!process.waitForFinished(15000)) {
            process.kill();
            return QStringLiteral("The client did not acknowledge the topology change in time.");
        }
        if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
            const QString details = QString::fromUtf8(process.readAllStandardError()).trimmed();
            return details.isEmpty() ? QStringLiteral("The client rejected the topology change.") : details;
        }
        return {};
    }

    QString ensureClientFirewall() override {
        if (firewallPermissionConfigured()) return {};
        QString ufw = QStandardPaths::findExecutable(QStringLiteral("ufw"));
        if (ufw.isEmpty() && QFileInfo::exists(QStringLiteral("/usr/bin/ufw")))
            ufw = QStringLiteral("/usr/bin/ufw");
        if (ufw.isEmpty() && QFileInfo::exists(QStringLiteral("/usr/sbin/ufw")))
            ufw = QStringLiteral("/usr/sbin/ufw");
        if (ufw.isEmpty()) return {};
        const QString subnet = detectedLanCidr();
        if (subnet.isEmpty())
            return QStringLiteral("Could not determine this iMac's local IPv4 subnet for the firewall rule.");
        QProcess rule;
        rule.start(QStringLiteral("pkexec"), {
            ufw, QStringLiteral("allow"), QStringLiteral("from"), subnet,
            QStringLiteral("to"), QStringLiteral("any"), QStringLiteral("port"),
            QStringLiteral("45231:45234"), QStringLiteral("proto"), QStringLiteral("tcp"),
        });
        if (!rule.waitForStarted())
            return QStringLiteral("Could not request administrator authorization for the firewall rule.");
        if (!rule.waitForFinished(60000)) {
            rule.kill();
            return QStringLiteral("Firewall authorization timed out.");
        }
        if (rule.exitStatus() != QProcess::NormalExit || rule.exitCode() != 0) {
            const QString details = QString::fromUtf8(rule.readAllStandardError()).trimmed();
            return details.isEmpty()
                ? QStringLiteral("Firewall access was not granted.") : details;
        }
        if (!rememberFirewallPermission())
            return QStringLiteral("Firewall rule was added, but CachyBridge could not remember the approval state.");
        return {};
    }

    QString save(const SetupDraft &draft) override {
        QTemporaryFile tokenFile;
        tokenFile.setAutoRemove(true);
        if (!tokenFile.open())
            return QStringLiteral("Could not create a private temporary pairing-token file.");
        tokenFile.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
        if (tokenFile.write(draft.pairingPsk.toUtf8()) != draft.pairingPsk.toUtf8().size()
            || tokenFile.write("\n") != 1 || !tokenFile.flush()) {
            return QStringLiteral("Could not write the private temporary pairing token.");
        }

        QStringList arguments{
            QStringLiteral("peer-add"),
            QStringLiteral("--local-name"), draft.hostName,
            QStringLiteral("--name"), draft.clientName,
            QStringLiteral("--host-endpoint"), draft.hostEndpoint,
            QStringLiteral("--client-endpoint"), draft.clientEndpoint,
            QStringLiteral("--placement"), placementName(draft.placement),
            QStringLiteral("--psk-file"), tokenFile.fileName(),
        };
        if (!configPath_.isEmpty())
            arguments << QStringLiteral("--config") << configPath_;
        if (draft.persistentPermissions)
            arguments << QStringLiteral("--persistent-permissions");

        QProcess process;
        process.start(cachybridge_, arguments);
        if (!process.waitForStarted())
            return QStringLiteral("Could not start %1: %2").arg(cachybridge_, process.errorString());
        if (!process.waitForFinished(15000)) {
            process.kill();
            return QStringLiteral("Saving configuration timed out.");
        }
        if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
            const auto details = QString::fromUtf8(process.readAllStandardError()).trimmed();
            return details.isEmpty() ? QStringLiteral("Configuration validation failed.") : details;
        }
        return {};
    }

private:
    QString cachybridge_;
    QString configPath_;
};

// The data plane deliberately has separate encrypted TCP channels for KVM
// input and clipboard transfers.  Poll their socket state rather than merely
// reporting whether a systemd unit was started: a unit can be running while it
// is waiting for a peer, a portal approval, or a reconnect.  The one-second
// timer doubles as a small, visible diagnostics heartbeat in the setup UI.
class ConnectionHeartbeatMonitor final : public QObject {
public:
    ConnectionHeartbeatMonitor(QLabel *label, QString channel, quint16 port, QObject *parent)
        : QObject(parent), label_(label), channel_(std::move(channel)), port_(port) {
        label_->setWordWrap(true);
        label_->setToolTip(QStringLiteral(
            "CachyBridge checks for an established encrypted TCP socket once per second. "
            "This diagnostic heartbeat distinguishes a running service from a live peer connection."));
        timer_.setInterval(1000);
        connect(&timer_, &QTimer::timeout, this, [this] { probe(); });
    }

    void start() {
        timer_.start();
        probe();
    }

private:
    void show(const QString &state, const QString &color) const {
        label_->setText(QStringLiteral("<span style=\"color:%1\"><b>%2</b></span> — %3")
            .arg(color, channel_, state));
    }

    void probe() {
        if (probe_)
            return;
        const QString ss = QStandardPaths::findExecutable(QStringLiteral("ss"));
        if (ss.isEmpty()) {
            show(QStringLiteral("diagnostics unavailable (the ss utility is missing)"),
                 QStringLiteral("#d97706"));
            return;
        }

        auto *process = new QProcess(this);
        probe_ = process;
        connect(process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
            [this, process](int exitCode, QProcess::ExitStatus status) {
                const QString now = QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss"));
                const QString output = QString::fromUtf8(process->readAllStandardOutput());
                const QStringList lines = output.split(u'\n', Qt::SkipEmptyParts);
                const bool connected = status == QProcess::NormalExit && exitCode == 0
                    && std::any_of(lines.cbegin(), lines.cend(), [this](const QString &line) {
                            return line.startsWith(QStringLiteral("ESTAB"))
                                && line.contains(QStringLiteral(":%1").arg(port_));
                        });
                if (connected) {
                    lastHealthyProbe_ = now;
                    show(QStringLiteral("connected · diagnostic heartbeat %1").arg(now),
                         QStringLiteral("#15803d"));
                } else if (lastHealthyProbe_.isEmpty()) {
                    show(QStringLiteral("waiting for a peer · checked %1").arg(now),
                         QStringLiteral("#b45309"));
                } else {
                    show(QStringLiteral("disconnected · last healthy heartbeat %1 · checked %2")
                             .arg(lastHealthyProbe_, now),
                         QStringLiteral("#b91c1c"));
                }
                probe_ = nullptr;
                process->deleteLater();
            });
        connect(process, &QProcess::errorOccurred, this,
            [this, process](QProcess::ProcessError) {
                if (process->state() == QProcess::NotRunning) {
                    show(QStringLiteral("diagnostic check could not run"), QStringLiteral("#d97706"));
                    probe_ = nullptr;
                }
            });
        process->start(ss, {QStringLiteral("-H"), QStringLiteral("-tn")});
    }

    QLabel *label_;
    QString channel_;
    quint16 port_;
    QTimer timer_;
    QProcess *probe_ = nullptr;
    QString lastHealthyProbe_;
};

class SetupWindow final : public QWidget {
public:
    explicit SetupWindow(std::unique_ptr<SetupStore> store, MachineRole role)
        : store_(std::move(store)), role_(role) {
        setWindowTitle(QStringLiteral("CachyBridge Setup"));
        setMinimumWidth(620);

        auto *heading = new QLabel(QStringLiteral("Pair two CachyOS desktops"));
        QFont headingFont = heading->font();
        headingFont.setPointSize(headingFont.pointSize() + 6);
        headingFont.setBold(true);
        heading->setFont(headingFont);

        auto *intro = new QLabel(role_ == MachineRole::Host
            ? QStringLiteral("Host / master mode: find a client, connect with its code, and place its display. "
                "No input portal is opened by this setup window.")
            : QStringLiteral("Client / slave mode: show a code and wait for the host to connect. "
                "No input portal is opened by this setup window."));
        intro->setWordWrap(true);

        hostName_ = new QLineEdit(QSysInfo::machineHostName());
        hostEndpoint_ = new QLineEdit(QStringLiteral("127.0.0.1:45231"));
        clientName_ = new QLineEdit(QStringLiteral("Client iMac"));
        clientEndpoint_ = new QLineEdit(QStringLiteral("127.0.0.1:45231"));
        pairingPsk_ = new QLineEdit;
        pairingPsk_->setEchoMode(QLineEdit::Password);
        pairingPsk_->setMaxLength(64);
        pairingPsk_->setPlaceholderText(QStringLiteral("64 hexadecimal characters"));

        pairingCode_ = new QLineEdit;
        pairingCode_->setPlaceholderText(QStringLiteral("ABCDE"));
        pairingCode_->setMaxLength(5);
        pairingAddress_ = new QLineEdit;
        pairingAddress_->setPlaceholderText(QStringLiteral("Client address, e.g. 192.168.2.24:45232"));

        auto *generateSecret = new QPushButton(QStringLiteral("Generate token"));
        connect(generateSecret, &QPushButton::clicked, this, [this] {
            QString error;
            const QString token = store_->generatePairingToken(&error);
            if (!error.isEmpty()) {
                QMessageBox::critical(this, QStringLiteral("Could not generate token"), error);
                return;
            }
            pairingPsk_->setText(token);
            pairingPsk_->setFocus();
        });

        auto *showSecret = new QCheckBox(QStringLiteral("Show token"));
        connect(showSecret, &QCheckBox::toggled, this, [this](bool checked) {
            pairingPsk_->setEchoMode(checked ? QLineEdit::Normal : QLineEdit::Password);
        });

        auto *form = new QFormLayout;
        form->addRow(QStringLiteral("Host name"), hostName_);
        form->addRow(QStringLiteral("Host IP and port"), hostEndpoint_);
        form->addRow(QStringLiteral("Client name"), clientName_);
        form->addRow(QStringLiteral("Client IP and port"), clientEndpoint_);
        auto *tokenRow = new QHBoxLayout;
        tokenRow->addWidget(pairingPsk_, 1);
        tokenRow->addWidget(generateSecret);
        tokenRow->addWidget(showSecret);
        form->addRow(QStringLiteral("Pairing PSK / token"), tokenRow);
        auto *manualPairing = new QWidget;
        auto *manualLayout = new QVBoxLayout(manualPairing);
        manualLayout->setContentsMargins(12, 12, 12, 12);
        auto *manualHeading = new QLabel(QStringLiteral("Advanced manual pairing"));
        manualHeading->setToolTip(QStringLiteral(
            "Use only for recovery or an explicitly managed PSK. Normal setup uses a short one-time code."));
        manualLayout->addWidget(manualHeading);
        manualLayout->addLayout(form);

        auto *easyPairing = new QWidget;
        auto *easyLayout = new QVBoxLayout(easyPairing);
        easyLayout->setContentsMargins(12, 12, 12, 12);
        auto *easyHeading = new QLabel(QStringLiteral("Pair with a five-character, single-use code"));
        easyLayout->addWidget(easyHeading);
        pairingStatus_ = new QLabel;
        pairingStatus_->setWordWrap(true);
        pairingStatus_->setStyleSheet(QStringLiteral(
            "QLabel { padding: 8px; border-radius: 6px; background: palette(alternate-base); }"));
        easyLayout->addWidget(pairingStatus_);
        clientCodeCard_ = new QWidget;
        clientCodeCard_->setStyleSheet(QStringLiteral(
            "QWidget { padding: 10px; border: 2px solid palette(highlight); border-radius: 8px; }"));
        auto *codeCardLayout = new QVBoxLayout(clientCodeCard_);
        auto *codeHeading = new QLabel(QStringLiteral("Give this code to the host"));
        codeHeading->setAlignment(Qt::AlignCenter);
        pairingCodeDisplay_ = new QLabel(QStringLiteral("—"));
        QFont codeFont = pairingCodeDisplay_->font();
        codeFont.setPointSize(std::max(codeFont.pointSize() + 18, 30));
        codeFont.setBold(true);
        pairingCodeDisplay_->setFont(codeFont);
        pairingCodeDisplay_->setAlignment(Qt::AlignCenter);
        pairingCodeDisplay_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        pairingAddressDisplay_ = new QLabel;
        pairingAddressDisplay_->setAlignment(Qt::AlignCenter);
        pairingAddressDisplay_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        codeCardLayout->addWidget(codeHeading);
        codeCardLayout->addWidget(pairingCodeDisplay_);
        codeCardLayout->addWidget(pairingAddressDisplay_);
        easyLayout->addWidget(clientCodeCard_);
        auto *hostButton = new QPushButton(QStringLiteral("Show one-time code on this client iMac"));
        hostButton->setToolTip(QStringLiteral(
            "Starts a five-minute listener. On the input-owner host, enter this client's LAN address and the displayed code."));
        connect(hostButton, &QPushButton::clicked, this, [this, hostButton] {
            if (hostPairingProcess_) {
                pairingStatus_->setText(QStringLiteral(
                    "This client is already waiting for a host to enter the displayed code."));
                return;
            }
            // The persistent client listener uses the same LAN-approved port
            // as one-time pairing. Stop it first so a re-pair never races a
            // running sharing session for that port.
            const QString systemctl = QStandardPaths::findExecutable(QStringLiteral("systemctl"));
            if (!systemctl.isEmpty()) {
                QProcess::execute(systemctl, {QStringLiteral("--user"), QStringLiteral("stop"),
                    QStringLiteral("cachybridge-seamless-client")});
            }
            QString error;
            const QString code = store_->generatePairingCode(&error);
            if (!error.isEmpty()) {
                QMessageBox::critical(this, QStringLiteral("Could not create code"), error);
                return;
            }
            SetupDraft draft{hostName_->text().trimmed(), hostEndpoint_->text().trimmed(),
                clientName_->text().trimmed(), clientEndpoint_->text().trimmed(), QString(),
                selectedPlacement(), persistent_->isChecked()};
            hostPairingProcess_ = new QProcess(this);
            const QString startError = store_->startPairClient(draft, code, hostPairingProcess_);
            if (!startError.isEmpty()) {
                hostPairingProcess_->deleteLater();
                hostPairingProcess_ = nullptr;
                QMessageBox::critical(this, QStringLiteral("Could not start pairing"), startError);
                return;
            }
            const QString address = localLanAddress();
            hostButton->setEnabled(false);
            pairingCodeDisplay_->setText(code);
            pairingAddressDisplay_->setText(QStringLiteral("Client IP: %1:45232").arg(address));
            clientCodeCard_->setVisible(true);
            pairingStatus_->setText(QStringLiteral(
                "Waiting for the host. This code expires in five minutes and works once."));
            connect(hostPairingProcess_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
                [this, hostButton](int exitCode, QProcess::ExitStatus status) {
                    const QString details = QString::fromUtf8(hostPairingProcess_->readAllStandardError()).trimmed();
                    const QString peerId = pairedPeerIdFromOutput(
                        QString::fromUtf8(hostPairingProcess_->readAllStandardOutput()));
                    hostPairingProcess_->deleteLater();
                    hostPairingProcess_ = nullptr;
                    hostButton->setEnabled(true);
                    if (status == QProcess::NormalExit && exitCode == 0 && !peerId.isEmpty()) {
                        const QString serviceError = startClientSession(peerId);
                        if (serviceError.isEmpty()) {
                            pairingStatus_->setText(QStringLiteral(
                                "Pairing complete. Approve the desktop-portal prompt if shown; this client is then ready for the host."));
                        } else {
                            pairingStatus_->setText(QStringLiteral(
                                "Pairing was saved, but the client listener could not start: %1").arg(serviceError));
                        }
                    } else {
                        pairingStatus_->setText(details.isEmpty()
                            ? QStringLiteral("Pairing ended. The code expired or was not completed.")
                            : QStringLiteral("Pairing ended: %1").arg(details));
                    }
                });
        });
        auto *firewallButton = new QPushButton(QStringLiteral("Allow CachyBridge on this LAN…"));
        firewallButton->setToolTip(QStringLiteral(
            "Optional one-time administrator action. It saves a persistent UFW rule for CachyBridge input, pairing, and clipboard ports."));
        if (firewallPermissionConfigured()) {
            firewallButton->setText(QStringLiteral("CachyBridge LAN access configured"));
            firewallButton->setEnabled(false);
        }
        connect(firewallButton, &QPushButton::clicked, this, [this, firewallButton] {
            const QString error = store_->ensureClientFirewall();
            if (!error.isEmpty()) {
                QMessageBox::warning(this, QStringLiteral("Could not update firewall"), error);
                return;
            }
            firewallButton->setText(QStringLiteral("CachyBridge LAN access configured"));
            firewallButton->setEnabled(false);
            QMessageBox::information(this, QStringLiteral("LAN firewall ready"),
                QStringLiteral("CachyBridge is allowed on this LAN. This rule is persistent; you will not be asked again."));
        });
        auto *clipboardSupport = new QPushButton;
        const auto refreshClipboardSupport = [clipboardSupport] {
            const bool available = clipboardToolsAvailable();
            clipboardSupport->setText(available
                ? QStringLiteral("Clipboard support installed")
                : QStringLiteral("Install clipboard support…"));
            clipboardSupport->setEnabled(!available);
        };
        refreshClipboardSupport();
        clipboardSupport->setToolTip(QStringLiteral(
            "CachyBridge shares text clipboard contents using wl-clipboard. This is a one-time system install on each iMac."));
        connect(clipboardSupport, &QPushButton::clicked, this, [this, clipboardSupport, refreshClipboardSupport] {
            QString pacman = QStandardPaths::findExecutable(QStringLiteral("pacman"));
            if (pacman.isEmpty() && QFileInfo::exists(QStringLiteral("/usr/bin/pacman")))
                pacman = QStringLiteral("/usr/bin/pacman");
            if (pacman.isEmpty()) {
                QMessageBox::warning(this, QStringLiteral("Could not install clipboard support"),
                    QStringLiteral("The pacman package manager is not available."));
                return;
            }
            QProcess install;
            install.start(QStringLiteral("pkexec"), {pacman, QStringLiteral("-S"),
                QStringLiteral("--needed"), QStringLiteral("--noconfirm"), QStringLiteral("wl-clipboard")});
            if (!install.waitForStarted()) {
                QMessageBox::warning(this, QStringLiteral("Could not start installation"),
                    QStringLiteral("Administrator authorization could not be started."));
                return;
            }
            if (!install.waitForFinished(60000)) {
                install.kill();
                QMessageBox::warning(this, QStringLiteral("Clipboard support installation timed out"),
                    QStringLiteral("Try again and approve the administrator prompt."));
                return;
            }
            if (install.exitStatus() != QProcess::NormalExit || install.exitCode() != 0) {
                const QString details = QString::fromUtf8(install.readAllStandardError()).trimmed();
                QMessageBox::warning(this, QStringLiteral("Clipboard support was not installed"),
                    details.isEmpty() ? QStringLiteral("Administrator authorization was not granted.") : details);
                return;
            }
            refreshClipboardSupport();
            QMessageBox::information(this, QStringLiteral("Clipboard support ready"),
                QStringLiteral("Restart the CachyBridge sharing session on both iMacs to begin syncing text."));
        });
        auto *joinButton = new QPushButton(QStringLiteral("Connect host to client with code"));
        connect(joinButton, &QPushButton::clicked, this, [this] {
            const PairJoinDraft draft{hostName_->text().trimmed(), pairingAddress_->text().trimmed(),
                pairingCode_->text().trimmed(), selectedPlacement(), persistent_->isChecked()};
            if (draft.localName.isEmpty() || draft.clientAddress.isEmpty() || draft.code.isEmpty()) {
                pairingStatus_->setText(QStringLiteral(
                    "Enter this host's name, the client address, and the displayed code."));
                return;
            }
            QString peerId;
            const QString error = store_->connectPairHost(draft, &peerId);
            if (!error.isEmpty()) {
                pairingStatus_->setText(QStringLiteral("Could not pair: %1").arg(error));
                return;
            }
            activePeerId_ = peerId;
            pairingStatus_->setText(QStringLiteral(
                "Pairing saved. Starting the sharing session; approve a portal prompt if Plasma shows one."));
            // The client starts RemoteDesktop and InputCapture portal sessions
            // before it opens its listener. The host CLI now waits up to a
            // minute for that listener, which covers a first-use portal prompt.
            QTimer::singleShot(3000, this, [this, peerId] {
                const QString serviceError = startHostSession(peerId);
                if (!serviceError.isEmpty()) {
                    pairingStatus_->setText(QStringLiteral(
                        "Pairing was saved, but the host session could not start: %1").arg(serviceError));
                    return;
                }
                pairingStatus_->setText(QStringLiteral(
                    "Host session started. It will wait for the client while any desktop-portal approval is completed."));
            });
        });
        auto *joinForm = new QFormLayout;
        joinForm->addRow(QStringLiteral("Client address"), pairingAddress_);
        joinForm->addRow(QStringLiteral("One-time code"), pairingCode_);
        auto *discoverButton = new QPushButton(QStringLiteral("Find nearby clients"));
        connect(discoverButton, &QPushButton::clicked, this, [this] {
            QString error;
            const QStringList clients = store_->discoverPairClients(&error);
            if (!error.isEmpty()) {
                pairingStatus_->setText(QStringLiteral("Discovery failed: %1").arg(error));
                return;
            }
            if (clients.isEmpty()) {
                pairingStatus_->setText(QStringLiteral(
                    "No client found. Open setup on the client and show its one-time code first."));
                return;
            }
            QString selected = clients.first();
            if (clients.size() > 1) {
                bool accepted = false;
                selected = QInputDialog::getItem(this, QStringLiteral("Choose a client"),
                    QStringLiteral("Nearby clients"), clients, 0, false, &accepted);
                if (!accepted) return;
            }
            const int separator = selected.indexOf(u'\t');
            if (separator <= 0) return;
            pairingAddress_->setText(selected.left(separator));
        });
        easyLayout->addWidget(firewallButton);
        easyLayout->addWidget(clipboardSupport);
        easyLayout->addWidget(hostButton);
        hostConnectPanel_ = new QWidget;
        auto *hostConnectLayout = new QVBoxLayout(hostConnectPanel_);
        hostConnectLayout->setContentsMargins(0, 0, 0, 0);
        hostConnectLayout->addLayout(joinForm);
        hostConnectLayout->addWidget(discoverButton);
        hostConnectLayout->addWidget(joinButton);
        easyLayout->addWidget(hostConnectPanel_);

        auto *placementBox = new QWidget;
        auto *placementLayout = new QVBoxLayout(placementBox);
        placementLayout->setContentsMargins(12, 12, 12, 12);
        auto *hint = new QLabel(QStringLiteral(
            "Drag the client tile left or right of the host. Tile sizes reflect the selected display resolutions. "
            "Apply & reconnect updates both iMacs and re-arms the matching cursor edge."));
        hint->setWordWrap(true);
        placementPreview_ = new DisplayLayoutPreview;
        clientWidth_ = new QSpinBox;
        clientHeight_ = new QSpinBox;
        for (auto *spin : {clientWidth_, clientHeight_}) {
            spin->setRange(640, 16384);
            spin->setSingleStep(16);
            spin->setSuffix(QStringLiteral(" px"));
        }
        clientWidth_->setValue(placementPreview_->clientResolution().width());
        clientHeight_->setValue(placementPreview_->clientResolution().height());
        connect(clientWidth_, qOverload<int>(&QSpinBox::valueChanged), this, [this] {
            placementPreview_->setClientResolution({clientWidth_->value(), clientHeight_->value()});
        });
        connect(clientHeight_, qOverload<int>(&QSpinBox::valueChanged), this, [this] {
            placementPreview_->setClientResolution({clientWidth_->value(), clientHeight_->value()});
        });
        auto *resolutionForm = new QFormLayout;
        resolutionForm->addRow(QStringLiteral("Client width"), clientWidth_);
        resolutionForm->addRow(QStringLiteral("Client height"), clientHeight_);
        placementLayout->addWidget(hint);
        placementLayout->addWidget(placementPreview_);
        placementLayout->addLayout(resolutionForm);
        auto *applyPlacement = new QPushButton(QStringLiteral("Apply & reconnect"));
        applyPlacement->setToolTip(QStringLiteral(
            "Saves this layout on both paired iMacs, releases active input, then starts a fresh host session."));
        connect(applyPlacement, &QPushButton::clicked, this, [this] {
            QString peerId = activePeerId_;
            if (peerId.isEmpty()) {
                QString error;
                const QStringList peers = store_->configuredPeers(&error);
                if (!error.isEmpty()) {
                    QMessageBox::warning(this, QStringLiteral("Could not read pairings"), error);
                    return;
                }
                if (peers.isEmpty()) {
                    QMessageBox::information(this, QStringLiteral("No paired client"),
                        QStringLiteral("Pair a client first, then return here to apply its placement."));
                    return;
                }
                QString selected = peers.first();
                if (peers.size() > 1) {
                    bool accepted = false;
                    selected = QInputDialog::getItem(this, QStringLiteral("Choose paired client"),
                        QStringLiteral("Client"), peers, 0, false, &accepted);
                    if (!accepted) return;
                }
                peerId = selected.section(u'\t', 0, 0);
            }
            const QString updateError = store_->applyTopology(peerId, selectedPlacement());
            if (!updateError.isEmpty()) {
                QMessageBox::warning(this, QStringLiteral("Could not apply placement"), updateError);
                return;
            }
            activePeerId_ = peerId;
            const QString serviceError = startHostSession(peerId);
            if (!serviceError.isEmpty()) {
                QMessageBox::warning(this, QStringLiteral("Placement saved, host not restarted"), serviceError);
                return;
            }
            QMessageBox::information(this, QStringLiteral("Placement applied"),
                QStringLiteral("The session is reconnecting with the new cursor boundary."));
        });
        placementLayout->addWidget(applyPlacement);

        persistent_ = new QCheckBox(
            QStringLiteral("Remember desktop portal permissions (recommended on these two iMacs)"));
        persistent_->setToolTip(QStringLiteral(
            "Stores portal-issued single-use restore tokens in the private CachyBridge configuration."));
        easyLayout->addWidget(persistent_);

        auto *saveButton = new QPushButton(QStringLiteral("Save manual pairing"));
        saveButton->setDefault(true);
        auto *cancel = new QPushButton(QStringLiteral("Cancel"));
        connect(cancel, &QPushButton::clicked, this, &QWidget::close);
        connect(saveButton, &QPushButton::clicked, this, [this] { save(); });
        auto *actions = new QHBoxLayout;
        actions->addStretch();
        actions->addWidget(cancel);
        actions->addWidget(saveButton);
        manualLayout->addStretch();
        manualLayout->addLayout(actions);

        auto *layout = new QVBoxLayout(this);
        layout->addWidget(heading);
        layout->addWidget(intro);
        layout->addSpacing(8);
        auto *tabs = new QTabWidget;
        tabs->addTab(easyPairing, QStringLiteral("Easy pairing"));
        tabs->addTab(manualPairing, QStringLiteral("Manual pairing"));
        tabs->addTab(placementBox, QStringLiteral("Client placement"));

        auto *connectionDiagnostics = new QWidget;
        auto *diagnosticsLayout = new QVBoxLayout(connectionDiagnostics);
        diagnosticsLayout->setContentsMargins(12, 12, 12, 12);
        auto *diagnosticsHeading = new QLabel(QStringLiteral("Live connection diagnostics"));
        QFont diagnosticsFont = diagnosticsHeading->font();
        diagnosticsFont.setBold(true);
        diagnosticsHeading->setFont(diagnosticsFont);
        auto *diagnosticsHint = new QLabel(QStringLiteral(
            "Each channel is checked every second. A green state means this iMac has an established, "
            "authenticated CachyBridge transport socket; it is more useful than only knowing that the service started."));
        diagnosticsHint->setWordWrap(true);
        auto *kvmStatus = new QLabel;
        auto *clipboardStatus = new QLabel;
        diagnosticsLayout->addWidget(diagnosticsHeading);
        diagnosticsLayout->addWidget(diagnosticsHint);
        diagnosticsLayout->addSpacing(8);
        diagnosticsLayout->addWidget(kvmStatus);
        diagnosticsLayout->addWidget(clipboardStatus);
        diagnosticsLayout->addStretch();
        tabs->addTab(connectionDiagnostics, QStringLiteral("Connections"));
        layout->addWidget(tabs, 1);

        auto *kvmHeartbeat = new ConnectionHeartbeatMonitor(
            kvmStatus, QStringLiteral("KVM input (TCP 45231)"), 45231, this);
        auto *clipboardHeartbeat = new ConnectionHeartbeatMonitor(
            clipboardStatus, QStringLiteral("Clipboard (TCP 45234)"), 45234, this);
        kvmHeartbeat->start();
        clipboardHeartbeat->start();

        hostButton->setVisible(role_ == MachineRole::Client);
        firewallButton->setVisible(role_ == MachineRole::Client);
        hostConnectPanel_->setVisible(role_ == MachineRole::Host);
        clientCodeCard_->setVisible(false);
        pairingStatus_->setText(role_ == MachineRole::Host
            ? QStringLiteral("Enter the client’s address and displayed code, or find a nearby client.")
            : QStringLiteral("Create a code here, then enter it from the host iMac."));
        tabs->setTabEnabled(2, role_ == MachineRole::Host);
    }

private:
    QSize logicalScreenSize() const {
        const auto *screen = QGuiApplication::primaryScreen();
        return screen ? screen->size() : QSize(2560, 1440);
    }

    QString startUserService(const QString &unit, const QStringList &command,
                             bool restartOnFailure = false) const {
        const QString systemdRun = QStandardPaths::findExecutable(QStringLiteral("systemd-run"));
        const QString systemctl = QStandardPaths::findExecutable(QStringLiteral("systemctl"));
        if (systemdRun.isEmpty() || systemctl.isEmpty())
            return QStringLiteral("systemd user services are not available on this desktop.");

        // Re-pairing replaces an old session safely: the old portal process is
        // stopped first, which releases any captured buttons and keys.
        QProcess::execute(systemctl, {QStringLiteral("--user"), QStringLiteral("stop"), unit});

        QStringList arguments{
            QStringLiteral("--user"), QStringLiteral("--unit=") + unit,
            QStringLiteral("--collect"), QStringLiteral("--property=Restart=")
                + (restartOnFailure ? QStringLiteral("on-failure") : QStringLiteral("no")),
        };
        for (const QString &name : {QStringLiteral("XDG_RUNTIME_DIR"),
                                    QStringLiteral("DBUS_SESSION_BUS_ADDRESS"),
                                    QStringLiteral("XDG_SESSION_TYPE"),
                                    QStringLiteral("WAYLAND_DISPLAY")}) {
            const QString value = qEnvironmentVariable(name.toUtf8().constData());
            if (!value.isEmpty())
                arguments << QStringLiteral("--setenv=") + name + u'=' + value;
        }
        arguments << bundledCliPath() << command;

        QProcess process;
        process.start(systemdRun, arguments);
        if (!process.waitForStarted() || !process.waitForFinished(5000)
            || process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
            const QString details = QString::fromUtf8(process.readAllStandardError()).trimmed();
            const QString reason = details.isEmpty() ? process.errorString() : details;
            logSetupDiagnostic(QStringLiteral("service launch failed"),
                QStringLiteral("unit=%1 program=%2 reason=%3").arg(unit, systemdRun, reason));
            return QStringLiteral("Could not start %1: %2").arg(unit, reason);
        }
        logSetupDiagnostic(QStringLiteral("service launched"), QStringLiteral("unit=%1").arg(unit));
        return {};
    }

    QString startClientSession(const QString &peerId) const {
        const QSize size = logicalScreenSize();
        return startUserService(QStringLiteral("cachybridge-seamless-client"), {
            QStringLiteral("seamless-client-config"), QStringLiteral("--peer"), peerId,
            QStringLiteral("--peer-width"), QString::number(size.width()),
            QStringLiteral("--peer-y"), QStringLiteral("0"),
        }, true);
    }

    QString startHostSession(const QString &peerId) const {
        const QSize local = logicalScreenSize();
        const QSize remote(clientWidth_->value(), clientHeight_->value());
        return startUserService(QStringLiteral("cachybridge-seamless-host"), {
            QStringLiteral("seamless-host-config"), QStringLiteral("--peer"), peerId,
            QStringLiteral("--local-width"), QString::number(local.width()),
            QStringLiteral("--local-height"), QString::number(local.height()),
            QStringLiteral("--peer-width"), QString::number(remote.width()),
            QStringLiteral("--peer-height"), QString::number(remote.height()),
            QStringLiteral("--peer-y"), QStringLiteral("0"),
        });
    }

    Placement selectedPlacement() const {
        return placementPreview_->placement();
    }

    static QString localLanAddress() {
        QProcess process;
        process.start(QStringLiteral("ip"), {
            QStringLiteral("-o"), QStringLiteral("-4"), QStringLiteral("addr"),
            QStringLiteral("show"), QStringLiteral("scope"), QStringLiteral("global")
        });
        if (process.waitForStarted() && process.waitForFinished(1000)
            && process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0) {
            const QStringList lines = QString::fromUtf8(process.readAllStandardOutput())
                .split(u'\n', Qt::SkipEmptyParts);
            for (const QString &line : lines) {
                const QStringList fields = line.simplified().split(u' ', Qt::SkipEmptyParts);
                const int inet = fields.indexOf(QStringLiteral("inet"));
                if (inet >= 0 && inet + 1 < fields.size()) {
                    const QString address = fields.at(inet + 1).section(u'/', 0, 0);
                    if (!address.startsWith(QStringLiteral("127."))) return address;
                }
            }
        }
        return QStringLiteral("<this iMac's LAN IP>");
    }

    void save() {
        const QString token = pairingPsk_->text().trimmed();
        const auto validName = [](const QString &name) {
            if (name.isEmpty() || name.size() > 80)
                return false;
            for (const QChar character : name) {
                if (!(character.unicode() < 128 && (character.isLetterOrNumber()
                      || character == u' ' || character == u'-'
                      || character == u'_' || character == u'.')))
                    return false;
            }
            return true;
        };
        const auto hex = [](QChar character) {
            const auto value = character.unicode();
            return (value >= u'0' && value <= u'9')
                || (value >= u'a' && value <= u'f')
                || (value >= u'A' && value <= u'F');
        };
        if (!validName(hostName_->text().trimmed()) || !validName(clientName_->text().trimmed())) {
            QMessageBox::warning(this, QStringLiteral("Invalid name"),
                QStringLiteral("Names must use 1–80 letters, digits, spaces, '.', '_' or '-'."));
            return;
        }
        if (token.size() != 64 || !std::all_of(token.cbegin(), token.cend(), hex)) {
            QMessageBox::warning(this, QStringLiteral("Invalid pairing token"),
                QStringLiteral("The pairing token must contain exactly 64 hexadecimal characters."));
            return;
        }
        SetupDraft draft{
            hostName_->text().trimmed(), hostEndpoint_->text().trimmed(),
            clientName_->text().trimmed(), clientEndpoint_->text().trimmed(),
            token, selectedPlacement(), persistent_->isChecked()
        };
        const QString error = store_->save(draft);
        if (!error.isEmpty()) {
            QMessageBox::critical(this, QStringLiteral("Could not save setup"), error);
            return;
        }
        QMessageBox::information(this, QStringLiteral("CachyBridge is configured"),
            QStringLiteral("The pairing and display placement were saved with private permissions."));
        close();
    }

    std::unique_ptr<SetupStore> store_;
    QLineEdit *hostName_ = nullptr;
    QLineEdit *hostEndpoint_ = nullptr;
    QLineEdit *clientName_ = nullptr;
    QLineEdit *clientEndpoint_ = nullptr;
    QLineEdit *pairingPsk_ = nullptr;
    QLineEdit *pairingCode_ = nullptr;
    QLineEdit *pairingAddress_ = nullptr;
    DisplayLayoutPreview *placementPreview_ = nullptr;
    QSpinBox *clientWidth_ = nullptr;
    QSpinBox *clientHeight_ = nullptr;
    QCheckBox *persistent_ = nullptr;
    QLabel *pairingStatus_ = nullptr;
    QWidget *clientCodeCard_ = nullptr;
    QLabel *pairingCodeDisplay_ = nullptr;
    QLabel *pairingAddressDisplay_ = nullptr;
    QProcess *hostPairingProcess_ = nullptr;
    QWidget *hostConnectPanel_ = nullptr;
    QString activePeerId_;
    MachineRole role_;
};

} // namespace

int main(int argc, char **argv) {
    QApplication application(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("CachyBridge Setup"));
    QCoreApplication::setOrganizationName(QStringLiteral("CachyOS"));

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("CachyBridge v4 setup wizard"));
    parser.addHelpOption();
    QCommandLineOption bridgeOption(QStringLiteral("cachybridge"),
        QStringLiteral("Path to the CachyBridge CLI"), QStringLiteral("path"),
        bundledCliPath());
    QCommandLineOption configOption(QStringLiteral("config"),
        QStringLiteral("Override the v4 configuration file"), QStringLiteral("path"));
    parser.addOption(bridgeOption);
    parser.addOption(configOption);
    parser.process(application);

    // The Start Menu launches this GUI directly. If it is already open, bring
    // that one forward instead of creating an ambiguous second setup window.
    QLocalServer controlServer;
    const QString controlName = setupControlServerName();
    if (!controlServer.listen(controlName)) {
        if (sendSetupCommand("activate"))
            return 0;
        QLocalServer::removeServer(controlName);
        if (!controlServer.listen(controlName)) {
            QMessageBox::critical(nullptr, QStringLiteral("Could not open CachyBridge"),
                QStringLiteral("The CachyBridge setup window control channel is unavailable."));
            return 1;
        }
    }

    RoleSelectionDialog roleDialog;
    QWidget *activeSetupWindow = nullptr;
    QObject::connect(&controlServer, &QLocalServer::newConnection, &application, [&] {
        while (QLocalSocket *socket = controlServer.nextPendingConnection()) {
            const auto handle = [&application, &roleDialog, &activeSetupWindow, socket] {
                const QByteArray command = socket->readAll().trimmed();
                QWidget *target = activeSetupWindow
                    ? activeSetupWindow : static_cast<QWidget *>(&roleDialog);
                if (command == "activate") {
                    target->showNormal();
                    target->raise();
                    target->activateWindow();
                } else if (command == "quit") {
                    if (activeSetupWindow)
                        activeSetupWindow->close();
                    roleDialog.reject();
                    application.quit();
                }
                socket->disconnectFromServer();
                socket->deleteLater();
            };
            QObject::connect(socket, &QLocalSocket::readyRead, &application, handle);
            if (socket->bytesAvailable() > 0)
                handle();
        }
    });
    if (roleDialog.exec() != QDialog::Accepted)
        return 0;
    SetupWindow window(std::make_unique<CliSetupStore>(
        parser.value(bridgeOption), parser.value(configOption)), roleDialog.role());
    activeSetupWindow = &window;
    window.show();
    return application.exec();
}
