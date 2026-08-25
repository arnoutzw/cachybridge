#include <QApplication>
#include <QAbstractItemView>
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
#include <QHostAddress>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QLocalServer>
#include <QLocalSocket>
#include <QMessageBox>
#include <QImage>
#include <QPixmap>
#include <QPlainTextEdit>
#include <QPainter>
#include <QPaintEvent>
#include <QProcess>
#include <QPushButton>
#include <QSaveFile>
#include <QScreen>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QSet>
#include <QSettings>
#include <QSpinBox>
#include <QSysInfo>
#include <QStandardPaths>
#include <QTemporaryFile>
#include <QTemporaryDir>
#include <QTabWidget>
#include <QTextStream>
#include <QTimer>
#include <QUdpSocket>
#include <QVBoxLayout>
#include <QVector>
#include <QWidget>

#include <algorithm>
#include <functional>
#include <cstring>
#include <memory>
#include <optional>

namespace {

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

bool trayIsRunning() {
    QLocalSocket socket;
    socket.connectToServer(trayControlServerName());
    if (!socket.waitForConnected(300))
        return false;
    socket.write("ping");
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

QString configuredLocalName() {
    QSettings settings(QStringLiteral("CachyOS"), QStringLiteral("CachyBridge Setup"));
    const QString name = settings.value(QStringLiteral("identity/name")).toString().trimmed();
    return name.isEmpty() ? QSysInfo::machineHostName() : name;
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

QString bundledTrayPath() {
    const QString adjacent = QCoreApplication::applicationDirPath()
        + QStringLiteral("/cachybridge-tray");
    if (QFileInfo(adjacent).isExecutable())
        return adjacent;
    return QStandardPaths::findExecutable(QStringLiteral("cachybridge-tray"));
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
        return !file.exists() || file.remove();
    }
    const QString tray = bundledTrayPath();
    if (tray.isEmpty() || !QDir().mkpath(QFileInfo(path).dir().absolutePath()))
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
        .arg(tray).toUtf8();
    if (file.write(desktop) != desktop.size())
        return false;
    file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    return file.commit();
}

void ensureTrayUtility() {
    if (trayIsRunning())
        return;
    const QString tray = bundledTrayPath();
    if (!tray.isEmpty())
        QProcess::startDetached(tray, {});
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

bool requestClientPairingCode(const QString &endpoint) {
    const int separator = endpoint.lastIndexOf(u':');
    if (separator <= 0)
        return false;
    QHostAddress address;
    bool portOk = false;
    const quint16 port = endpoint.sliced(separator + 1).toUShort(&portOk);
    if (!address.setAddress(endpoint.left(separator)) || !portOk || port == 0)
        return false;
    constexpr auto request = "CachyBridgePairRequest/1";
    QUdpSocket socket;
    return socket.writeDatagram(request, address, port) == qint64(strlen(request));
}

bool requestClientReconnect(const QString &endpoint) {
    const int separator = endpoint.lastIndexOf(u':');
    if (separator <= 0)
        return false;
    QHostAddress address;
    if (!address.setAddress(endpoint.left(separator)))
        return false;
    constexpr auto request = "CachyBridgeReconnect/1";
    QUdpSocket socket;
    return socket.writeDatagram(request, address, 45'232) == qint64(strlen(request));
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
    return directory.isEmpty() ? QString() : directory + QStringLiteral("/firewall-v3-ready");
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
    if (!file.open(QIODevice::WriteOnly) || file.write("tcp=45231:45234\nudp=45232\n") < 0)
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
        hostLabel->setBrush(QBrush(Qt::white));
        hostLabel->setPos(hostRect.center() - hostLabel->boundingRect().center());
        hostLabel->setParentItem(hostTile);

        QRectF clientRect(0, 0, client.width(), client.height());
        clientTile_ = new DraggableClientTile(clientRect, [this](QPointF point) { snapFrom(point); });
        clientTile_->setPen(QPen(palette().highlight(), 2));
        clientTile_->setBrush(QBrush(palette().alternateBase()));
        scene_.addItem(clientTile_);
        auto *clientLabel = scene_.addSimpleText(
            QStringLiteral("Client\n%1 × %2").arg(clientResolution_.width()).arg(clientResolution_.height()));
        clientLabel->setBrush(QBrush(Qt::white));
        clientLabel->setPos(clientRect.center() - clientLabel->boundingRect().center());
        clientLabel->setParentItem(clientTile_);

        placeClient(hostRect, clientRect);
        hostRect_ = hostRect;
        // Fit the actual display arrangement, not a fixed symmetric canvas:
        // this keeps both tiles centered after the client is moved left/right.
        scene_.setSceneRect(scene_.itemsBoundingRect().adjusted(-40, -40, 40, 40));
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

std::optional<MachineRole> configuredRole(const QString &cachybridge) {
    QProcess process;
    process.start(cachybridge, {QStringLiteral("peer-list")});
    if (!process.waitForStarted() || !process.waitForFinished(3000)
        || process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        return std::nullopt;
    }
    const QString line = QString::fromUtf8(process.readAllStandardOutput())
        .split(u'\n', Qt::SkipEmptyParts).value(0);
    if (line.isEmpty())
        return std::nullopt;

    QSettings settings;
    const QString saved = settings.value(QStringLiteral("startup/role")).toString();
    if (saved == QStringLiteral("host")) return MachineRole::Host;
    if (saved == QStringLiteral("client")) return MachineRole::Client;

    // v4 stores the peer relative to this machine. Existing installations did
    // not record an explicit role; retain the standard left-host/right-client
    // arrangement without showing setup again. A later session start records
    // the explicit role for all future launches.
    return line.section(u'\t', 2, 2) == QStringLiteral("right")
        ? MachineRole::Client : MachineRole::Host;
}

QString endpointAddress(const QString &endpoint) {
    const QString trimmed = endpoint.trimmed();
    if (trimmed.startsWith(u'[')) {
        const int closingBracket = trimmed.indexOf(u']');
        if (closingBracket > 1)
            return trimmed.sliced(1, closingBracket - 1);
    }
    const int portSeparator = trimmed.lastIndexOf(u':');
    return portSeparator > 0 ? trimmed.left(portSeparator) : QString();
}

// A discovered client advertises its short-lived pairing port (45232), while
// a live session uses the encrypted KVM and clipboard ports (45231/45234).
// Compare addresses, rather than full endpoints, so the nearby list can show
// the actual live connection state without exposing any pairing secret.
QSet<QString> connectedCachyBridgeAddresses() {
    QString ss = QStandardPaths::findExecutable(QStringLiteral("ss"));
    if (ss.isEmpty() && QFileInfo::exists(QStringLiteral("/usr/bin/ss")))
        ss = QStringLiteral("/usr/bin/ss");
    if (ss.isEmpty())
        return {};

    QProcess process;
    process.start(ss, {QStringLiteral("-H"), QStringLiteral("-tn")});
    if (!process.waitForStarted() || !process.waitForFinished(1500)
        || process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        return {};
    }

    QSet<QString> addresses;
    const QStringList lines = QString::fromUtf8(process.readAllStandardOutput())
        .split(u'\n', Qt::SkipEmptyParts);
    for (const QString &line : lines) {
        const QStringList fields = line.simplified().split(u' ', Qt::SkipEmptyParts);
        QStringList endpoints;
        bool bridgeConnection = false;
        for (const QString &field : fields) {
            const int separator = field.lastIndexOf(u':');
            if (separator <= 0)
                continue;
            endpoints << field;
            bool portIsValid = false;
            const quint16 port = field.sliced(separator + 1).toUShort(&portIsValid);
            bridgeConnection |= portIsValid && (port == 45231 || port == 45234);
        }
        // On the client, ss reports 45231/45234 on the *local* endpoint.
        // Record both ends of a known CachyBridge connection so each role can
        // match its paired peer's LAN address.
        if (!bridgeConnection)
            continue;
        for (const QString &endpoint : endpoints) {
            const QString address = endpointAddress(endpoint);
            QHostAddress parsedAddress;
            if (parsedAddress.setAddress(address))
                addresses.insert(parsedAddress.toString());
        }
    }
    return addresses;
}

bool isAddressConnected(const QString &endpoint, const QSet<QString> &connectedAddresses) {
    QHostAddress address;
    return address.setAddress(endpointAddress(endpoint))
        && connectedAddresses.contains(address.toString());
}

QString peerIdForClientEndpoint(const QStringList &peers, const QString &endpoint) {
    const QString address = endpointAddress(endpoint);
    for (const QString &peer : peers) {
        // peer-list: id, name, relative placement, local endpoint, remote endpoint
        if (endpointAddress(peer.section(u'\t', 4, 4)) == address)
            return peer.section(u'\t', 0, 0);
    }
    return {};
}

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
    virtual QString clientDisplaySize(const QString &peerId, QSize *size) = 0;
    virtual QString removePeer(const QString &peerId) = 0;
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

    QString clientDisplaySize(const QString &peerId, QSize *size) override {
        QProcess process;
        QStringList arguments{QStringLiteral("peer-display"), QStringLiteral("--peer"), peerId};
        if (!configPath_.isEmpty()) arguments << QStringLiteral("--config") << configPath_;
        process.start(cachybridge_, arguments);
        if (!process.waitForStarted() || !process.waitForFinished(7000)
            || process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
            const QString details = QString::fromUtf8(process.readAllStandardError()).trimmed();
            return details.isEmpty()
                ? QStringLiteral("Could not read the paired client's display.") : details;
        }
        const QString reported = QString::fromUtf8(process.readAllStandardOutput()).trimmed();
        const QStringList dimensions = reported.split(u'x');
        bool widthOk = false;
        bool heightOk = false;
        const int width = dimensions.value(0).toInt(&widthOk);
        const int height = dimensions.value(1).toInt(&heightOk);
        if (dimensions.size() != 2 || !widthOk || !heightOk || width <= 0 || height <= 0)
            return QStringLiteral("The paired client returned an invalid display size.");
        *size = QSize(width, height);
        return {};
    }

    QString removePeer(const QString &peerId) override {
        QProcess process;
        QStringList arguments{QStringLiteral("peer-remove"), QStringLiteral("--peer"), peerId};
        if (!configPath_.isEmpty()) arguments << QStringLiteral("--config") << configPath_;
        process.start(cachybridge_, arguments);
        if (!process.waitForStarted() || !process.waitForFinished(5000)
            || process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
            const QString details = QString::fromUtf8(process.readAllStandardError()).trimmed();
            return details.isEmpty() ? QStringLiteral("Could not remove the saved pairing.") : details;
        }
        return {};
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
        QProcess pairingRule;
        pairingRule.start(QStringLiteral("pkexec"), {
            ufw, QStringLiteral("allow"), QStringLiteral("from"), subnet,
            QStringLiteral("to"), QStringLiteral("any"), QStringLiteral("port"),
            QStringLiteral("45232"), QStringLiteral("proto"), QStringLiteral("udp"),
        });
        if (!pairingRule.waitForStarted())
            return QStringLiteral("Could not request administrator authorization for pairing discovery.");
        if (!pairingRule.waitForFinished(60000)) {
            pairingRule.kill();
            return QStringLiteral("Pairing-discovery firewall authorization timed out.");
        }
        if (pairingRule.exitStatus() != QProcess::NormalExit || pairingRule.exitCode() != 0) {
            const QString details = QString::fromUtf8(pairingRule.readAllStandardError()).trimmed();
            return details.isEmpty()
                ? QStringLiteral("LAN pairing requests were not allowed.") : details;
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

class FrameTimePlot final : public QWidget {
public:
    explicit FrameTimePlot(QWidget *parent = nullptr) : QWidget(parent) {
        setMinimumHeight(280);
    }

    void setSamples(QVector<double> samples) {
        samples_ = std::move(samples);
        update();
    }

protected:
    void paintEvent(QPaintEvent *) override {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        const QRectF bounds = rect().adjusted(52, 26, -16, -38);
        const QColor foreground = palette().color(QPalette::Text);
        const QColor border = palette().color(QPalette::Mid);
        const QColor surface = palette().color(QPalette::AlternateBase);
        painter.fillRect(rect(), surface);
        painter.setPen(QPen(border, 1));
        painter.drawRect(bounds);
        painter.setPen(foreground);
        painter.drawText(QRectF(8, 4, width() - 16, 20), Qt::AlignLeft | Qt::AlignVCenter,
            QStringLiteral("Frame time — latest active input frames"));
        painter.drawText(QRectF(bounds.left(), bounds.bottom() + 8, bounds.width(), 20),
            Qt::AlignCenter, QStringLiteral("Time →"));
        if (samples_.isEmpty()) {
            painter.drawText(bounds, Qt::AlignCenter,
                QStringLiteral("Waiting for active remote input…"));
            return;
        }

        QVector<double> ordered = samples_;
        std::sort(ordered.begin(), ordered.end());
        const double p95 = ordered.at(static_cast<int>((ordered.size() - 1) * 0.95));
        const double maximum = ordered.last();
        // Keep normal 120/60 Hz detail visible. Rare spikes are marked at the
        // chart ceiling instead of flattening the entire live trace.
        const double yMaximum = std::max(20.0, std::min(50.0, std::ceil(p95 / 5.0) * 5.0));
        const auto yFor = [&bounds, yMaximum](double milliseconds) {
            return bounds.bottom() - std::min(milliseconds, yMaximum) / yMaximum * bounds.height();
        };
        const auto xFor = [&bounds, count = samples_.size()](int index) {
            return count <= 1 ? bounds.left()
                : bounds.left() + static_cast<double>(index) / (count - 1) * bounds.width();
        };

        painter.setPen(QPen(border, 1, Qt::DashLine));
        for (double milliseconds : {8.33, 16.67}) {
            const double y = yFor(milliseconds);
            painter.drawLine(QPointF(bounds.left(), y), QPointF(bounds.right(), y));
            painter.drawText(QRectF(2, y - 9, 46, 18), Qt::AlignRight | Qt::AlignVCenter,
                QString::number(milliseconds, 'f', 1));
        }
        painter.setPen(QPen(border, 1));
        painter.drawText(QRectF(2, bounds.top() - 9, 46, 18), Qt::AlignRight | Qt::AlignVCenter,
            QString::number(yMaximum, 'f', 0));
        painter.drawText(QRectF(2, bounds.bottom() - 9, 46, 18), Qt::AlignRight | Qt::AlignVCenter,
            QStringLiteral("0"));

        QPainterPath path;
        for (int index = 0; index < samples_.size(); ++index) {
            const QPointF point(xFor(index), yFor(samples_.at(index)));
            if (index == 0) path.moveTo(point); else path.lineTo(point);
        }
        painter.setPen(QPen(palette().color(QPalette::Highlight), 1.6));
        painter.drawPath(path);
        painter.setPen(QPen(QColor(QStringLiteral("#dc2626")), 3));
        for (int index = 0; index < samples_.size(); ++index) {
            if (samples_.at(index) > 16.67)
                painter.drawPoint(QPointF(xFor(index), yFor(samples_.at(index))));
        }
        painter.setPen(foreground);
        painter.drawText(QRectF(bounds.left(), bounds.top() - 1, bounds.width(), 20),
            Qt::AlignRight | Qt::AlignVCenter,
            QStringLiteral("latest %1 ms · p95 %2 ms · max %3 ms")
                .arg(samples_.last(), 0, 'f', 2).arg(p95, 0, 'f', 2).arg(maximum, 0, 'f', 2));
    }

private:
    QVector<double> samples_;
};

class SetupWindow final : public QWidget {
public:
    explicit SetupWindow(std::unique_ptr<SetupStore> store, MachineRole role)
        : store_(std::move(store)), role_(role) {
        setWindowTitle(QStringLiteral("CachyBridge"));
        setMinimumWidth(580);

        auto *roleBanner = new QLabel(role_ == MachineRole::Host
            ? QStringLiteral("Host · controls mouse and keyboard")
            : QStringLiteral("Client · receives shared input"));
        QFont roleFont = roleBanner->font();
        roleFont.setPointSize(roleFont.pointSize() + 1);
        roleFont.setBold(true);
        roleBanner->setFont(roleFont);
        roleBanner->setStyleSheet(QStringLiteral(
            "QLabel { padding: 2px 0; color: palette(highlight); }"));

        localName_ = configuredLocalName();
        pairingCode_ = new QLineEdit;
        pairingCode_->setPlaceholderText(QStringLiteral("ABCDE"));
        pairingCode_->setMaxLength(5);
        pairingAddress_ = new QLineEdit(this);
        pairingAddress_->setVisible(false);

        auto *easyPairing = new QWidget;
        auto *easyLayout = new QVBoxLayout(easyPairing);
        easyLayout->setContentsMargins(12, 12, 12, 12);
        localNameEditor_ = new QLineEdit(localName_);
        localNameEditor_->setMaxLength(80);
        localNameEditor_->setToolTip(QStringLiteral(
            "A CachyBridge label for this iMac. It does not change the system hostname."));
        auto *identityForm = new QFormLayout;
        identityForm->addRow(QStringLiteral("This iMac"), localNameEditor_);
        easyLayout->addLayout(identityForm);
        connect(localNameEditor_, &QLineEdit::editingFinished, this, [this] {
            saveLocalName();
        });
        pairingStatus_ = new QLabel;
        pairingStatus_->setWordWrap(true);
        pairingStatus_->setStyleSheet(QStringLiteral(
            "QLabel { padding: 4px 0; color: palette(mid); }"));
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
            if (!saveLocalName())
                return;
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
            SetupDraft draft{localName_, {}, {}, {}, {}, selectedPlacement(), true};
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
            "Optional one-time administrator action. It saves persistent UFW rules for CachyBridge input, clipboard, and host-led pairing requests."));
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
        auto *nearbyClients = new QListWidget;
        nearbyClients->setMinimumHeight(62);
        nearbyClients->setMaximumHeight(160);
        nearbyClients->setSelectionMode(QAbstractItemView::SingleSelection);
        nearbyClients->setToolTip(QStringLiteral(
            "Only client iMacs with the CachyBridge tray open appear here."));
        nearbyClients->setStyleSheet(QStringLiteral(
            "QListWidget { border: 1px solid palette(mid); border-radius: 6px; }"
            "QListWidget::item { border-bottom: 1px solid palette(mid); }"));
        auto *joinButton = new QPushButton(QStringLiteral("Pair selected client"));
        joinButton->setEnabled(false);
        auto *pairingEntry = new QWidget;
        auto *pairingEntryLayout = new QVBoxLayout(pairingEntry);
        pairingEntryLayout->setContentsMargins(0, 0, 0, 0);
        pairingEntry->setVisible(false);
        auto *connectionEntry = new QWidget;
        auto *connectionLayout = new QVBoxLayout(connectionEntry);
        connectionLayout->setContentsMargins(0, 0, 0, 0);
        auto *connectButton = new QPushButton(QStringLiteral("Connect client"));
        connectionLayout->addWidget(connectButton);
        connectionEntry->setVisible(false);
        QFont pairingCodeFont = pairingCode_->font();
        pairingCodeFont.setPointSize(pairingCodeFont.pointSize() + 6);
        pairingCodeFont.setBold(true);
        pairingCode_->setFont(pairingCodeFont);
        connect(joinButton, &QPushButton::clicked, this, [this] {
            if (!saveLocalName())
                return;
            const PairJoinDraft draft{localName_, pairingAddress_->text().trimmed(),
                pairingCode_->text().trimmed(), selectedPlacement(), true};
            if (draft.localName.isEmpty() || draft.clientAddress.isEmpty() || draft.code.isEmpty()) {
                pairingStatus_->setText(QStringLiteral(
                    "Select a nearby client, then enter the five-character code shown on that client."));
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
        joinForm->addRow(QStringLiteral("Pairing code"), pairingCode_);
        pairingEntryLayout->addLayout(joinForm);
        pairingEntryLayout->addWidget(joinButton);
        connect(connectButton, &QPushButton::clicked, this, [this, connectButton] {
            const QString peerId = connectButton->property("peerId").toString();
            const QString endpoint = connectButton->property("endpoint").toString();
            if (peerId.isEmpty() || endpoint.isEmpty())
                return;
            if (!requestClientReconnect(endpoint)) {
                pairingStatus_->setText(QStringLiteral(
                    "Could not contact the client tray. Open CachyBridge on the client, then try again."));
                return;
            }
            activePeerId_ = peerId;
            connectButton->setEnabled(false);
            pairingStatus_->setText(QStringLiteral("Starting the client, then connecting…"));
            QTimer::singleShot(1200, this, [this, connectButton, peerId] {
                QSize remote;
                const QString displayError = store_->clientDisplaySize(peerId, &remote);
                if (displayError.isEmpty())
                    placementPreview_->setClientResolution(remote);
                const QString serviceError = startHostSession(peerId);
                connectButton->setEnabled(true);
                if (!serviceError.isEmpty()) {
                    pairingStatus_->setText(QStringLiteral("Could not start the connection: %1").arg(serviceError));
                    return;
                }
                pairingStatus_->setText(displayError.isEmpty()
                    ? QStringLiteral("Connecting with the client’s current display size.")
                    : QStringLiteral("Connecting. Client display size will refresh when it is online."));
            });
        });
        const auto refreshNearbyClients = [this, nearbyClients, joinButton] {
            QString error;
            const QStringList clients = store_->discoverPairClients(&error);
            QString pairingError;
            const QStringList peers = store_->configuredPeers(&pairingError);
            const QSet<QString> connectedAddresses = connectedCachyBridgeAddresses();
            QSettings settings;
            const QString currentPeerId = activePeerId_.isEmpty()
                ? settings.value(QStringLiteral("startup/peer-id")).toString()
                : activePeerId_;
            nearbyClients->clear();
            joinButton->setEnabled(false);
            if (!error.isEmpty()) {
                pairingStatus_->setText(QStringLiteral("Discovery failed: %1").arg(error));
                return;
            }
            if (clients.isEmpty()) {
                pairingStatus_->setText(QStringLiteral(
                    "No ready clients found. Open the CachyBridge tray on the client iMac, then refresh."));
                return;
            }
            for (const QString &client : clients) {
                const int separator = client.indexOf(u'\t');
                if (separator <= 0)
                    continue;
                const QString endpoint = client.left(separator);
                QString name = client.sliced(separator + 1).trimmed();
                name.remove(QStringLiteral("CachyBridge "), Qt::CaseInsensitive);
                const bool connected = isAddressConnected(endpoint, connectedAddresses);
                QString peerId = pairingError.isEmpty()
                    ? peerIdForClientEndpoint(peers, endpoint) : QString();
                // Discovery only advertises a temporary pairing endpoint. If
                // there is one saved client, it is unambiguously that client
                // even when the discovery metadata is stale or incomplete.
                if (peerId.isEmpty() && pairingError.isEmpty() && peers.size() == 1)
                    peerId = peers.first().section(u'\t', 0, 0);
                const bool paired = !peerId.isEmpty();
                const bool current = paired && peerId.compare(currentPeerId, Qt::CaseInsensitive) == 0;
                const QString state = connected
                    ? (current ? QStringLiteral("CONNECTED · CURRENT") : QStringLiteral("CONNECTED"))
                    : (current ? QStringLiteral("CURRENT PAIRING")
                        : (paired ? QStringLiteral("PAIRED") : QStringLiteral("READY TO PAIR")));
                const QString stateStyle = connected
                    ? QStringLiteral("color: #15803d; background: #dcfce7;")
                    : (paired ? QStringLiteral("color: #1d4ed8; background: #dbeafe;")
                        : QStringLiteral("color: palette(text); background: palette(alternate-base);"));
                auto *item = new QListWidgetItem(nearbyClients);
                item->setData(Qt::UserRole, endpoint);
                item->setData(Qt::UserRole + 1, paired);
                item->setData(Qt::UserRole + 2, connected);
                item->setData(Qt::UserRole + 3, current);
                item->setData(Qt::UserRole + 4, peerId);
                item->setSizeHint(QSize(0, 54));
                item->setToolTip(connected
                    ? QStringLiteral("A live CachyBridge KVM or clipboard connection is active.")
                    : (paired ? QStringLiteral("This iMac already has a saved CachyBridge pairing.")
                        : QStringLiteral("This iMac is available for a new pairing.")));
                auto *row = new QWidget;
                auto *rowLayout = new QHBoxLayout(row);
                rowLayout->setContentsMargins(10, 5, 10, 5);
                auto *details = new QVBoxLayout;
                details->setSpacing(0);
                auto *nameLabel = new QLabel(name);
                QFont nameFont = nameLabel->font();
                nameFont.setBold(true);
                nameLabel->setFont(nameFont);
                details->addWidget(nameLabel);
                auto *endpointLabel = new QLabel(endpointAddress(endpoint));
                endpointLabel->setStyleSheet(QStringLiteral("color: white;"));
                details->addWidget(endpointLabel);
                auto *stateLabel = new QLabel(state);
                stateLabel->setStyleSheet(QStringLiteral(
                    "QLabel { %1 padding: 3px 6px; border-radius: 4px; font-weight: 600; }").arg(stateStyle));
                rowLayout->addLayout(details, 1);
                rowLayout->addWidget(stateLabel);
                nearbyClients->setItemWidget(item, row);
            }
            pairingStatus_->clear();
        };
        connect(nearbyClients, &QListWidget::currentItemChanged, this,
            [this, joinButton, pairingEntry, connectionEntry, connectButton]
            (QListWidgetItem *item, QListWidgetItem *) {
                joinButton->setEnabled(false);
                pairingEntry->setVisible(false);
                connectionEntry->setVisible(false);
                if (!item)
                    return;
                const bool paired = item->data(Qt::UserRole + 1).toBool();
                const bool connected = item->data(Qt::UserRole + 2).toBool();
                const bool current = item->data(Qt::UserRole + 3).toBool();
                if (paired) {
                    connectButton->setProperty("peerId", item->data(Qt::UserRole + 4));
                    connectButton->setProperty("endpoint", item->data(Qt::UserRole));
                    connectButton->setText(connected
                        ? QStringLiteral("Reconnect client") : QStringLiteral("Connect client"));
                    connectionEntry->setVisible(true);
                    pairingStatus_->setText(connected
                        ? QStringLiteral("This is %1 active CachyBridge connection.")
                            .arg(current ? QStringLiteral("the current") : QStringLiteral("a"))
                        : QStringLiteral("This iMac is already paired. Reconnect it from the CachyBridge tray menu."));
                    return;
                }
                const QString endpoint = item->data(Qt::UserRole).toString();
                if (!requestClientPairingCode(endpoint)) {
                    pairingStatus_->setText(QStringLiteral(
                        "Could not ask this client to show a pairing code. Refresh and try again."));
                    return;
                }
                pairingAddress_->setText(endpoint);
                pairingCode_->clear();
                pairingCode_->setFocus();
                joinButton->setEnabled(true);
                pairingEntry->setVisible(true);
                pairingStatus_->setText(QStringLiteral(
                    "The selected client is showing a large pairing code. Enter it here, then pair."));
            });
        easyLayout->addWidget(firewallButton);
        easyLayout->addWidget(clipboardSupport);
        easyLayout->addWidget(hostButton);
        hostConnectPanel_ = new QWidget;
        auto *hostConnectLayout = new QVBoxLayout(hostConnectPanel_);
        hostConnectLayout->setContentsMargins(0, 0, 0, 0);
        hostConnectLayout->addWidget(new QLabel(QStringLiteral("Client iMacs")));
        hostConnectLayout->addWidget(nearbyClients);
        hostConnectLayout->addWidget(pairingEntry);
        hostConnectLayout->addWidget(connectionEntry);
        easyLayout->addWidget(hostConnectPanel_);

        auto *clientHostPanel = new QWidget;
        auto *clientHostLayout = new QVBoxLayout(clientHostPanel);
        clientHostLayout->setContentsMargins(0, 0, 0, 0);
        auto *knownHosts = new QListWidget;
        knownHosts->setMinimumHeight(62);
        knownHosts->setMaximumHeight(100);
        knownHosts->setFocusPolicy(Qt::NoFocus);
        knownHosts->setStyleSheet(QStringLiteral(
            "QListWidget { border: 1px solid palette(mid); border-radius: 6px; }"));
        clientHostLayout->addWidget(new QLabel(QStringLiteral("Host iMac")));
        clientHostLayout->addWidget(knownHosts);
        easyLayout->addWidget(clientHostPanel);
        const auto refreshClientHost = [this, knownHosts] {
            QString error;
            const QStringList peers = store_->configuredPeers(&error);
            knownHosts->clear();
            if (!error.isEmpty() || peers.isEmpty()) {
                new QListWidgetItem(QStringLiteral("No host is paired yet."), knownHosts);
                return;
            }
            QSettings settings;
            const QString currentPeerId = activePeerId_.isEmpty()
                ? settings.value(QStringLiteral("startup/peer-id")).toString()
                : activePeerId_;
            QString peer;
            for (const QString &candidate : peers) {
                if (candidate.section(u'\t', 0, 0).compare(currentPeerId, Qt::CaseInsensitive) == 0) {
                    peer = candidate;
                    break;
                }
            }
            if (peer.isEmpty())
                peer = peers.first();
            const QString hostName = peer.section(u'\t', 1, 1);
            const QString hostEndpoint = peer.section(u'\t', 3, 3);
            const bool connected = isAddressConnected(hostEndpoint, connectedCachyBridgeAddresses());
            auto *item = new QListWidgetItem(knownHosts);
            item->setSizeHint(QSize(0, 54));
            auto *row = new QWidget;
            auto *rowLayout = new QHBoxLayout(row);
            rowLayout->setContentsMargins(10, 5, 10, 5);
            auto *details = new QVBoxLayout;
            details->setSpacing(0);
            auto *nameLabel = new QLabel(hostName);
            QFont nameFont = nameLabel->font();
            nameFont.setBold(true);
            nameLabel->setFont(nameFont);
            auto *endpointLabel = new QLabel(endpointAddress(hostEndpoint));
            endpointLabel->setStyleSheet(QStringLiteral("color: white;"));
            details->addWidget(nameLabel);
            details->addWidget(endpointLabel);
            auto *state = new QLabel(connected ? QStringLiteral("CONNECTED") : QStringLiteral("PAIRED"));
            state->setStyleSheet(QStringLiteral(
                "QLabel { color: %1; background: %2; padding: 3px 6px; "
                "border-radius: 4px; font-weight: 600; }")
                .arg(connected ? QStringLiteral("#15803d") : QStringLiteral("#1d4ed8"),
                     connected ? QStringLiteral("#dcfce7") : QStringLiteral("#dbeafe")));
            rowLayout->addLayout(details, 1);
            rowLayout->addWidget(state);
            knownHosts->setItemWidget(item, row);
        };
        if (role_ == MachineRole::Host) {
            QTimer::singleShot(0, this, refreshNearbyClients);
            // A client Setup window starts its tray utility asynchronously.
            // Refresh idle lists so that client appears without requiring the
            // host user to close/reopen this already-visible window.
            auto *discoveryRefresh = new QTimer(this);
            discoveryRefresh->setInterval(3000);
            connect(discoveryRefresh, &QTimer::timeout, this,
                [nearbyClients, refreshNearbyClients] {
                    if (!nearbyClients->currentItem())
                        refreshNearbyClients();
            });
            discoveryRefresh->start();
        } else {
            QTimer::singleShot(0, this, refreshClientHost);
            auto *hostRefresh = new QTimer(this);
            hostRefresh->setInterval(2000);
            connect(hostRefresh, &QTimer::timeout, this, refreshClientHost);
            hostRefresh->start();
        }

        auto *unpairButton = new QPushButton(QStringLiteral("Unpair…"));
        unpairButton->setFlat(true);
        unpairButton->setStyleSheet(QStringLiteral(
            "QPushButton { color: palette(link); padding: 4px; }"));
        unpairButton->setToolTip(QStringLiteral(
            "Stops sharing and removes the trusted pairing and local portal permissions from this iMac."));
        connect(unpairButton, &QPushButton::clicked, this, [this, unpairButton] {
            QString selectionError;
            const QString peerId = configuredPeerIdForUnpair(&selectionError);
            if (peerId.isEmpty()) {
                QMessageBox::information(this, QStringLiteral("No pairing to remove"),
                    selectionError.isEmpty()
                        ? QStringLiteral("This iMac has no saved CachyBridge pairing.")
                        : selectionError);
                return;
            }
            const auto answer = QMessageBox::warning(this, QStringLiteral("Unpair this iMac?"),
                QStringLiteral("This immediately stops sharing and removes this iMac's saved trust key "
                    "and portal permissions. To revoke the pairing on both iMacs, use Unpair on the "
                    "other iMac too."),
                QMessageBox::Cancel | QMessageBox::Yes, QMessageBox::Cancel);
            if (answer != QMessageBox::Yes)
                return;

            unpairButton->setEnabled(false);
            const QString error = store_->removePeer(peerId);
            if (!error.isEmpty()) {
                unpairButton->setEnabled(true);
                QMessageBox::warning(this, QStringLiteral("Could not unpair"), error);
                return;
            }
            stopSharing();
            clearStartupSession();
            activePeerId_.clear();
            pairingStatus_->setText(QStringLiteral(
                "This iMac is unpaired. Use Unpair on the other iMac to remove its saved key too."));
            QMessageBox::information(this, QStringLiteral("This iMac is unpaired"),
                QStringLiteral("Sharing has stopped and the local CachyBridge pairing was removed."));
        });
        auto *startAtLogin = new QCheckBox(QStringLiteral("Start CachyBridge at login"));
        startAtLogin->setToolTip(QStringLiteral(
            "Starts the tray utility and restores the saved pairing after you sign in."));
        QSettings startupSettings;
        startAtLogin->setChecked(startupSettings.value(QStringLiteral("startup/enabled"), false).toBool());
        connect(startAtLogin, &QCheckBox::toggled, this, [startAtLogin](bool enabled) {
            if (!setLoginAutostart(enabled)) {
                QSignalBlocker blocker(startAtLogin);
                startAtLogin->setChecked(!enabled);
                QMessageBox::warning(startAtLogin, QStringLiteral("Could not update start at login"),
                    QStringLiteral("CachyBridge could not update its desktop autostart entry."));
                return;
            }
            QSettings settings;
            settings.setValue(QStringLiteral("startup/enabled"), enabled);
            settings.sync();
        });
        easyLayout->addWidget(startAtLogin);
        easyLayout->addWidget(unpairButton, 0, Qt::AlignRight);

        auto *placementBox = new QWidget;
        auto *placementLayout = new QVBoxLayout(placementBox);
        placementLayout->setContentsMargins(12, 12, 12, 12);
        auto *hint = new QLabel(QStringLiteral(
            "Drag the client tile left or right of the host. The client display size is read from the paired iMac. "
            "Apply & reconnect updates both iMacs and re-arms the matching cursor edge."));
        hint->setWordWrap(true);
        placementPreview_ = new DisplayLayoutPreview;
        auto *clientDisplay = new QLabel(QStringLiteral("Client display: not fetched"));
        clientDisplay->setStyleSheet(QStringLiteral("QLabel { color: palette(mid); }"));
        auto *refreshClientDisplay = new QPushButton(QStringLiteral("Refresh client display"));
        const auto fetchClientDisplay = [this, clientDisplay] {
            QString peerId = activePeerId_;
            if (peerId.isEmpty()) {
                QSettings settings;
                peerId = settings.value(QStringLiteral("startup/peer-id")).toString();
            }
            if (peerId.isEmpty()) {
                QString error;
                const QStringList peers = store_->configuredPeers(&error);
                if (error.isEmpty() && peers.size() == 1)
                    peerId = peers.first().section(u'\t', 0, 0);
            }
            if (peerId.isEmpty()) {
                clientDisplay->setText(QStringLiteral("Client display: pair a client first"));
                return;
            }
            QSize size;
            const QString error = store_->clientDisplaySize(peerId, &size);
            if (!error.isEmpty()) {
                clientDisplay->setText(QStringLiteral("Client display: unavailable until the client connects"));
                return;
            }
            activePeerId_ = peerId;
            placementPreview_->setClientResolution(size);
            clientDisplay->setText(QStringLiteral("Client display: %1 × %2 (live)")
                .arg(size.width()).arg(size.height()));
        };
        connect(refreshClientDisplay, &QPushButton::clicked, this, fetchClientDisplay);
        placementLayout->addWidget(hint);
        placementLayout->addWidget(placementPreview_);
        placementLayout->addWidget(clientDisplay);
        placementLayout->addWidget(refreshClientDisplay, 0, Qt::AlignLeft);
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

        auto *clipboardViewer = new QWidget;
        auto *clipboardLayout = new QVBoxLayout(clipboardViewer);
        clipboardLayout->setContentsMargins(12, 12, 12, 12);
        auto *clipboardHeading = new QLabel(QStringLiteral("Current local clipboard"));
        QFont clipboardFont = clipboardHeading->font();
        clipboardFont.setBold(true);
        clipboardHeading->setFont(clipboardFont);
        auto *clipboardHint = new QLabel(QStringLiteral(
            "This is the item CachyBridge can send to the paired iMac. Text and file lists are shown below; images are previewed."));
        clipboardHint->setWordWrap(true);
        auto *clipboardSummary = new QLabel;
        clipboardSummary->setWordWrap(true);
        clipboardSummary->setStyleSheet(QStringLiteral(
            "QLabel { padding: 8px; border-radius: 6px; background: palette(alternate-base); }"));
        auto *clipboardPreview = new QPlainTextEdit;
        clipboardPreview->setReadOnly(true);
        clipboardPreview->setPlaceholderText(QStringLiteral("Nothing to display yet."));
        clipboardPreview->setMinimumHeight(180);
        auto *clipboardImage = new QLabel;
        clipboardImage->setAlignment(Qt::AlignCenter);
        clipboardImage->setMinimumHeight(180);
        clipboardImage->setVisible(false);
        auto *refreshClipboard = new QPushButton(QStringLiteral("Refresh clipboard"));
        const auto showClipboard = [clipboardSummary, clipboardPreview, clipboardImage] {
            const QString wlPaste = clipboardToolPath(QStringLiteral("wl-paste"));
            clipboardImage->clear();
            clipboardImage->setVisible(false);
            clipboardPreview->setVisible(true);
            clipboardPreview->clear();
            if (wlPaste.isEmpty()) {
                clipboardSummary->setText(QStringLiteral(
                    "Clipboard support is not installed. Install wl-clipboard from Easy pairing first."));
                return;
            }
            QProcess typesProcess;
            typesProcess.start(wlPaste, {QStringLiteral("--list-types")});
            if (!typesProcess.waitForStarted() || !typesProcess.waitForFinished(1000)
                || typesProcess.exitStatus() != QProcess::NormalExit || typesProcess.exitCode() != 0) {
                clipboardSummary->setText(QStringLiteral("The local clipboard is currently unavailable."));
                return;
            }
            const QStringList types = QString::fromUtf8(typesProcess.readAllStandardOutput())
                .split(u'\n', Qt::SkipEmptyParts);
            if (types.isEmpty()) {
                clipboardSummary->setText(QStringLiteral("The local clipboard is empty."));
                return;
            }
            QString mime;
            if (types.contains(QStringLiteral("text/uri-list")))
                mime = QStringLiteral("text/uri-list");
            else {
                for (const QString &candidate : {QStringLiteral("text/plain"),
                                                  QStringLiteral("text/plain;charset=utf-8"),
                                                  QStringLiteral("image/png"),
                                                  QStringLiteral("image/jpeg"),
                                                  QStringLiteral("image/webp")}) {
                    if (types.contains(candidate)) {
                        mime = candidate;
                        break;
                    }
                }
            }
            if (mime.isEmpty()) {
                clipboardSummary->setText(QStringLiteral("Clipboard type is not shared by CachyBridge: %1")
                    .arg(types.join(QStringLiteral(", "))));
                return;
            }
            QProcess contentProcess;
            contentProcess.start(wlPaste, {QStringLiteral("--no-newline"),
                                           QStringLiteral("--type"), mime});
            if (!contentProcess.waitForStarted() || !contentProcess.waitForFinished(1500)
                || contentProcess.exitStatus() != QProcess::NormalExit || contentProcess.exitCode() != 0) {
                clipboardSummary->setText(QStringLiteral("Could not read the %1 clipboard item.").arg(mime));
                return;
            }
            const QByteArray content = contentProcess.readAllStandardOutput();
            if (mime.startsWith(QStringLiteral("image/"))) {
                QImage image;
                if (!image.loadFromData(content)) {
                    clipboardSummary->setText(QStringLiteral("Image clipboard (%1, %2 bytes) could not be previewed.")
                        .arg(mime).arg(content.size()));
                    return;
                }
                clipboardSummary->setText(QStringLiteral("Image clipboard: %1 × %2 pixels (%3, %4 bytes)")
                    .arg(image.width()).arg(image.height()).arg(mime).arg(content.size()));
                clipboardImage->setPixmap(QPixmap::fromImage(image).scaled(
                    520, 320, Qt::KeepAspectRatio, Qt::SmoothTransformation));
                clipboardPreview->setVisible(false);
                clipboardImage->setVisible(true);
                return;
            }
            const QString display = QString::fromUtf8(content);
            constexpr qsizetype previewLimit = 64 * 1024;
            clipboardSummary->setText(mime == QStringLiteral("text/uri-list")
                ? QStringLiteral("File clipboard (%1 bytes)").arg(content.size())
                : QStringLiteral("Text clipboard (%1 bytes)").arg(content.size()));
            clipboardPreview->setPlainText(display.left(previewLimit)
                + (display.size() > previewLimit ? QStringLiteral("\n\n[preview truncated]") : QString()));
        };
        connect(refreshClipboard, &QPushButton::clicked, this, showClipboard);
        clipboardLayout->addWidget(clipboardHeading);
        clipboardLayout->addWidget(clipboardHint);
        clipboardLayout->addWidget(clipboardSummary);
        clipboardLayout->addWidget(clipboardPreview, 1);
        clipboardLayout->addWidget(clipboardImage, 1);
        clipboardLayout->addWidget(refreshClipboard);
        showClipboard();

        auto *diagnosticsViewer = new QWidget;
        auto *diagnosticsLayout = new QVBoxLayout(diagnosticsViewer);
        diagnosticsLayout->setContentsMargins(12, 12, 12, 12);
        auto *diagnosticsHeading = new QLabel(QStringLiteral("Live input performance"));
        QFont diagnosticsFont = diagnosticsHeading->font();
        diagnosticsFont.setBold(true);
        diagnosticsHeading->setFont(diagnosticsFont);
        auto *diagnosticsHint = new QLabel(QStringLiteral(
            "Time runs left to right; frame time is in milliseconds. The dashed guides mark 120 Hz (8.33 ms) and 60 Hz (16.67 ms). "
            "Red points are slower than 60 Hz. Idle pauses are excluded."));
        diagnosticsHint->setWordWrap(true);
        auto *frameTimePlot = new FrameTimePlot;
        auto *diagnosticsStatus = new QLabel(QStringLiteral(
            "Waiting for active remote input to collect frame-time samples."));
        diagnosticsStatus->setWordWrap(true);
        auto *refreshDiagnostics = new QPushButton(QStringLiteral("Refresh diagnostics"));
        diagnosticsLayout->addWidget(diagnosticsHeading);
        diagnosticsLayout->addWidget(diagnosticsHint);
        diagnosticsLayout->addWidget(frameTimePlot, 1);
        diagnosticsLayout->addWidget(diagnosticsStatus);
        diagnosticsLayout->addWidget(refreshDiagnostics, 0, Qt::AlignLeft);

        const QString diagnosticsFile = QDir(qEnvironmentVariable("XDG_RUNTIME_DIR"))
            .filePath(role_ == MachineRole::Host
                ? QStringLiteral("cachybridge/frame-times-capture.csv")
                : QStringLiteral("cachybridge/frame-times-injection.csv"));
        const auto refreshPerformanceDiagnostics = [frameTimePlot, diagnosticsStatus, diagnosticsFile] {
            QFile file(diagnosticsFile);
            if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
                frameTimePlot->setSamples({});
                diagnosticsStatus->setText(QStringLiteral(
                    "Waiting for active remote input to collect frame-time samples."));
                return;
            }
            QVector<double> samples;
            for (const QStringView value : QStringView(QString::fromUtf8(file.readAll())).split(u',')) {
                bool valid = false;
                const double milliseconds = value.trimmed().toDouble(&valid);
                if (valid && milliseconds >= 0.0)
                    samples << milliseconds;
            }
            if (samples.isEmpty()) {
                frameTimePlot->setSamples({});
                diagnosticsStatus->setText(QStringLiteral(
                    "Waiting for active remote input to collect frame-time samples."));
                return;
            }
            const int sampleCount = samples.size();
            frameTimePlot->setSamples(std::move(samples));
            diagnosticsStatus->setText(QStringLiteral(
                "Live at 60 Hz · rolling window of %1 active input frames").arg(sampleCount));
        };
        connect(refreshDiagnostics, &QPushButton::clicked, this, refreshPerformanceDiagnostics);
        auto *diagnosticsTimer = new QTimer(this);
        diagnosticsTimer->setInterval(16);
        connect(diagnosticsTimer, &QTimer::timeout, this, refreshPerformanceDiagnostics);
        diagnosticsTimer->start();

        auto *layout = new QVBoxLayout(this);
        layout->addWidget(roleBanner);
        auto *tabs = new QTabWidget;
        tabs->addTab(easyPairing, QStringLiteral("Connect"));
        tabs->addTab(clipboardViewer, QStringLiteral("Clipboard"));
        tabs->addTab(placementBox, QStringLiteral("Displays"));
        tabs->addTab(diagnosticsViewer, QStringLiteral("Diagnostics"));
        connect(tabs, &QTabWidget::currentChanged, this,
            [tabs, clipboardViewer, placementBox, diagnosticsViewer, showClipboard, fetchClientDisplay, refreshPerformanceDiagnostics](int) {
            if (tabs->currentWidget() == clipboardViewer)
                showClipboard();
            if (tabs->currentWidget() == placementBox)
                fetchClientDisplay();
            if (tabs->currentWidget() == diagnosticsViewer)
                refreshPerformanceDiagnostics();
        });

        layout->addWidget(tabs, 1);

        auto *statusBar = new QWidget;
        statusBar->setStyleSheet(QStringLiteral(
            "QWidget { background: palette(alternate-base); border-radius: 6px; } "
            "QLabel { padding: 6px 10px; }"));
        auto *statusLayout = new QHBoxLayout(statusBar);
        statusLayout->setContentsMargins(4, 2, 4, 2);
        auto *kvmStatus = new QLabel;
        auto *clipboardStatus = new QLabel;
        statusLayout->addWidget(kvmStatus, 1);
        statusLayout->addWidget(clipboardStatus, 1);
        layout->addWidget(statusBar);

        auto *kvmHeartbeat = new ConnectionHeartbeatMonitor(
            kvmStatus, QStringLiteral("KVM input (TCP 45231)"), 45231, this);
        auto *clipboardHeartbeat = new ConnectionHeartbeatMonitor(
            clipboardStatus, QStringLiteral("Clipboard (TCP 45234)"), 45234, this);
        kvmHeartbeat->start();
        clipboardHeartbeat->start();

        hostButton->setVisible(false);
        firewallButton->setVisible(role_ == MachineRole::Client && !firewallPermissionConfigured());
        clipboardSupport->setVisible(!clipboardToolsAvailable());
        hostConnectPanel_->setVisible(role_ == MachineRole::Host);
        clientHostPanel->setVisible(role_ == MachineRole::Client);
        clientCodeCard_->setVisible(false);
        pairingStatus_->setText(role_ == MachineRole::Host
            ? QStringLiteral("Select a nearby client iMac to request its pairing code.")
            : QStringLiteral("Keep the CachyBridge tray open. A host can then discover this client and request a pairing code."));
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
        rememberStartupSession(peerId, MachineRole::Client, size);
        return startUserService(QStringLiteral("cachybridge-seamless-client"), {
            QStringLiteral("seamless-client-config"), QStringLiteral("--peer"), peerId,
            QStringLiteral("--peer-width"), QString::number(size.width()),
            QStringLiteral("--peer-y"), QStringLiteral("0"),
        }, true);
    }

    QString configuredPeerIdForUnpair(QString *error) {
        QString storedPeerId;
        {
            QSettings settings;
            storedPeerId = settings.value(QStringLiteral("startup/peer-id")).toString();
        }
        if (!activePeerId_.isEmpty())
            storedPeerId = activePeerId_;

        const QStringList peers = store_->configuredPeers(error);
        if (!error->isEmpty() || peers.isEmpty())
            return {};
        for (const QString &peer : peers) {
            if (peer.section(u'\t', 0, 0).compare(storedPeerId, Qt::CaseInsensitive) == 0)
                return storedPeerId;
        }
        if (peers.size() == 1)
            return peers.first().section(u'\t', 0, 0);

        QStringList labels;
        for (const QString &peer : peers) {
            labels << QStringLiteral("%1 — %2")
                .arg(peer.section(u'\t', 1, 1), peer.section(u'\t', 4, 4));
        }
        bool accepted = false;
        const QString selected = QInputDialog::getItem(this, QStringLiteral("Choose pairing to unpair"),
            QStringLiteral("Paired iMac"), labels, 0, false, &accepted);
        if (!accepted)
            return {};
        return peers.value(labels.indexOf(selected)).section(u'\t', 0, 0);
    }

    void stopSharing() const {
        const QString systemctl = QStandardPaths::findExecutable(QStringLiteral("systemctl"));
        if (!systemctl.isEmpty()) {
            QProcess::execute(systemctl, {QStringLiteral("--user"), QStringLiteral("stop"),
                QStringLiteral("cachybridge-seamless-host"),
                QStringLiteral("cachybridge-seamless-client")});
        }
    }

    void clearStartupSession() const {
        QSettings settings;
        settings.remove(QStringLiteral("startup/peer-id"));
        settings.remove(QStringLiteral("startup/role"));
        settings.remove(QStringLiteral("startup/peer-width"));
        settings.remove(QStringLiteral("startup/peer-height"));
        settings.sync();
    }

    QString startHostSession(const QString &peerId) const {
        const QSize local = logicalScreenSize();
        const QSize remote = placementPreview_->clientResolution();
        rememberStartupSession(peerId, MachineRole::Host, remote);
        return startUserService(QStringLiteral("cachybridge-seamless-host"), {
            QStringLiteral("seamless-host-config"), QStringLiteral("--peer"), peerId,
            QStringLiteral("--local-width"), QString::number(local.width()),
            QStringLiteral("--local-height"), QString::number(local.height()),
            QStringLiteral("--peer-width"), QString::number(remote.width()),
            QStringLiteral("--peer-height"), QString::number(remote.height()),
            QStringLiteral("--peer-y"), QStringLiteral("0"),
        });
    }

    void rememberStartupSession(const QString &peerId, MachineRole role,
                                const QSize &peerResolution) const {
        QSettings settings;
        settings.setValue(QStringLiteral("startup/peer-id"), peerId);
        settings.setValue(QStringLiteral("startup/role"),
            role == MachineRole::Host ? QStringLiteral("host") : QStringLiteral("client"));
        settings.setValue(QStringLiteral("startup/peer-width"), peerResolution.width());
        settings.setValue(QStringLiteral("startup/peer-height"), peerResolution.height());
        settings.sync();
    }

    Placement selectedPlacement() const {
        return placementPreview_->placement();
    }

    bool saveLocalName() {
        if (!localNameEditor_)
            return true;
        const QString candidate = localNameEditor_->text().trimmed();
        const bool valid = !candidate.isEmpty() && candidate.size() <= 80
            && std::all_of(candidate.cbegin(), candidate.cend(), [](QChar character) {
                return character.isLetterOrNumber() && character.unicode() <= 0x7f
                    || character == u' ' || character == u'.'
                    || character == u'_' || character == u'-';
            });
        if (!valid) {
            pairingStatus_->setText(QStringLiteral(
                "This iMac name must be 1–80 ASCII letters, digits, spaces, '.', '_' or '-'."));
            localNameEditor_->setFocus();
            return false;
        }
        if (candidate == localName_)
            return true;
        localName_ = candidate;
        QSettings settings(QStringLiteral("CachyOS"), QStringLiteral("CachyBridge Setup"));
        settings.setValue(QStringLiteral("identity/name"), localName_);
        settings.sync();
        sendTrayCommand("refresh-identity");
        return true;
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

    std::unique_ptr<SetupStore> store_;
    QLineEdit *localNameEditor_ = nullptr;
    QLineEdit *pairingCode_ = nullptr;
    QLineEdit *pairingAddress_ = nullptr;
    DisplayLayoutPreview *placementPreview_ = nullptr;
    QLabel *pairingStatus_ = nullptr;
    QWidget *clientCodeCard_ = nullptr;
    QLabel *pairingCodeDisplay_ = nullptr;
    QLabel *pairingAddressDisplay_ = nullptr;
    QProcess *hostPairingProcess_ = nullptr;
    QWidget *hostConnectPanel_ = nullptr;
    QString localName_;
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
    const std::optional<MachineRole> existingRole = configuredRole(parser.value(bridgeOption));
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
    const MachineRole role = existingRole.has_value() ? *existingRole : [&roleDialog] {
        return roleDialog.exec() == QDialog::Accepted
            ? std::optional<MachineRole>(roleDialog.role()) : std::nullopt;
    }().value_or(MachineRole::Host);
    if (!existingRole.has_value() && roleDialog.result() != QDialog::Accepted)
        return 0;
    {
        QSettings settings;
        settings.setValue(QStringLiteral("startup/role"),
            role == MachineRole::Host ? QStringLiteral("host") : QStringLiteral("client"));
        settings.sync();
    }
    // The Start Menu opens Setup directly. Keep the long-lived tray utility
    // running alongside it: it owns discovery and makes the app reachable
    // when Setup is closed.
    ensureTrayUtility();
    SetupWindow window(std::make_unique<CliSetupStore>(
        parser.value(bridgeOption), parser.value(configOption)), role);
    activeSetupWindow = &window;
    window.show();
    return application.exec();
}
