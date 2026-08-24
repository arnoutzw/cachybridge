#include <QApplication>
#include <QCheckBox>
#include <QCommandLineParser>
#include <QDialog>
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
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QSaveFile>
#include <QScreen>
#include <QSpinBox>
#include <QSysInfo>
#include <QTemporaryFile>
#include <QTemporaryDir>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <functional>
#include <memory>

namespace {

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
        if (std::abs(delta.x()) >= std::abs(delta.y()))
            placement_ = delta.x() < 0 ? Placement::Left : Placement::Right;
        else
            placement_ = delta.y() < 0 ? Placement::Above : Placement::Below;
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
    virtual QString connectPairHost(const PairJoinDraft &draft) = 0;
    virtual QStringList discoverPairClients(QString *error) = 0;
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
        if (!process.waitForStarted() || !process.waitForFinished(15000)
            || process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
            const auto details = QString::fromUtf8(process.readAllStandardError()).trimmed();
            *error = details.isEmpty()
                ? QStringLiteral("The one-time-code generator failed.") : details;
            return {};
        }
        const QString code = QString::fromUtf8(process.readAllStandardOutput()).trimmed();
        if (code.size() != 5) {
            *error = QStringLiteral("The code generator returned an unexpected value.");
            return {};
        }
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

    QString connectPairHost(const PairJoinDraft &draft) override {
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
        if (!process.waitForFinished(15000)) {
            process.kill();
            return QStringLiteral("Pairing timed out. Check the host address and the displayed code.");
        }
        if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
            const auto details = QString::fromUtf8(process.readAllStandardError()).trimmed();
            return details.isEmpty() ? QStringLiteral("Pairing was rejected or expired.") : details;
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

        auto *easyPairing = new QGroupBox(QStringLiteral("Easy one-time pairing (recommended)"));
        auto *easyLayout = new QVBoxLayout(easyPairing);
        auto *hostButton = new QPushButton(QStringLiteral("Show one-time code on this client iMac"));
        hostButton->setToolTip(QStringLiteral(
            "Starts a five-minute listener. On the input-owner host, enter this client's LAN address and the displayed code."));
        connect(hostButton, &QPushButton::clicked, this, [this, hostButton] {
            if (hostPairingProcess_) {
                QMessageBox::information(this, QStringLiteral("Pairing is already open"),
                    QStringLiteral("This iMac is already waiting for one device to join."));
                return;
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
            QMessageBox::information(this, QStringLiteral("Pairing code — valid for five minutes"),
                QStringLiteral("On the input-owner host, choose ‘Connect host to client with code’ and enter:\n\n"
                    "Client address: %1:45232\nCode: %2\n\nThis code works once and is not saved.")
                    .arg(address, code));
            connect(hostPairingProcess_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
                [this, hostButton](int exitCode, QProcess::ExitStatus status) {
                    const QString details = QString::fromUtf8(hostPairingProcess_->readAllStandardError()).trimmed();
                    hostPairingProcess_->deleteLater();
                    hostPairingProcess_ = nullptr;
                    hostButton->setEnabled(true);
                    if (status == QProcess::NormalExit && exitCode == 0)
                        QMessageBox::information(this, QStringLiteral("Pairing complete"),
                            QStringLiteral("The input-owner host was saved on this client iMac with private permissions."));
                    else
                        QMessageBox::warning(this, QStringLiteral("Pairing ended"),
                            details.isEmpty() ? QStringLiteral("The code expired or pairing was not completed.") : details);
                });
        });
        auto *joinButton = new QPushButton(QStringLiteral("Connect host to client with code"));
        connect(joinButton, &QPushButton::clicked, this, [this] {
            const PairJoinDraft draft{hostName_->text().trimmed(), pairingAddress_->text().trimmed(),
                pairingCode_->text().trimmed(), selectedPlacement(), persistent_->isChecked()};
            if (draft.localName.isEmpty() || draft.clientAddress.isEmpty() || draft.code.isEmpty()) {
                QMessageBox::warning(this, QStringLiteral("Pairing details needed"),
                    QStringLiteral("Enter this host's name, the client address, and its displayed code."));
                return;
            }
            const QString error = store_->connectPairHost(draft);
            if (!error.isEmpty()) {
                QMessageBox::warning(this, QStringLiteral("Could not join"), error);
                return;
            }
            QMessageBox::information(this, QStringLiteral("Pairing complete"),
                QStringLiteral("The client was saved on this host iMac with private permissions."));
        });
        auto *joinForm = new QFormLayout;
        joinForm->addRow(QStringLiteral("Client address"), pairingAddress_);
        joinForm->addRow(QStringLiteral("One-time code"), pairingCode_);
        auto *discoverButton = new QPushButton(QStringLiteral("Find nearby clients"));
        connect(discoverButton, &QPushButton::clicked, this, [this] {
            QString error;
            const QStringList clients = store_->discoverPairClients(&error);
            if (!error.isEmpty()) {
                QMessageBox::warning(this, QStringLiteral("Discovery failed"), error);
                return;
            }
            if (clients.isEmpty()) {
                QMessageBox::information(this, QStringLiteral("No client found"),
                    QStringLiteral("Open setup on the client and choose ‘Show one-time code on this client iMac’."));
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
        easyLayout->addWidget(hostButton);
        hostConnectPanel_ = new QWidget;
        auto *hostConnectLayout = new QVBoxLayout(hostConnectPanel_);
        hostConnectLayout->setContentsMargins(0, 0, 0, 0);
        hostConnectLayout->addLayout(joinForm);
        hostConnectLayout->addWidget(discoverButton);
        hostConnectLayout->addWidget(joinButton);
        easyLayout->addWidget(hostConnectPanel_);

        auto *placementBox = new QGroupBox(QStringLiteral("Client placement"));
        auto *placementLayout = new QVBoxLayout(placementBox);
        auto *hint = new QLabel(QStringLiteral(
            "Drag the client tile to an edge of the host tile. Tile sizes reflect the selected display resolutions."));
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

        persistent_ = new QCheckBox(
            QStringLiteral("Remember desktop portal permissions (recommended on these two iMacs)"));
        persistent_->setToolTip(QStringLiteral(
            "Stores portal-issued single-use restore tokens in the private CachyBridge configuration."));

        auto *saveButton = new QPushButton(QStringLiteral("Save manual pairing"));
        saveButton->setDefault(true);
        auto *cancel = new QPushButton(QStringLiteral("Cancel"));
        connect(cancel, &QPushButton::clicked, this, &QWidget::close);
        connect(saveButton, &QPushButton::clicked, this, [this] { save(); });
        auto *actions = new QHBoxLayout;
        actions->addStretch();
        actions->addWidget(cancel);
        actions->addWidget(saveButton);

        auto *layout = new QVBoxLayout(this);
        layout->addWidget(heading);
        layout->addWidget(intro);
        layout->addSpacing(8);
        layout->addWidget(easyPairing);
        layout->addLayout(form);
        layout->addWidget(placementBox);
        layout->addWidget(persistent_);
        layout->addLayout(actions);

        hostButton->setVisible(role_ == MachineRole::Client);
        hostConnectPanel_->setVisible(role_ == MachineRole::Host);
        placementBox->setVisible(role_ == MachineRole::Host);
    }

private:
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
    QProcess *hostPairingProcess_ = nullptr;
    QWidget *hostConnectPanel_ = nullptr;
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
        QStringLiteral("cachybridge"));
    QCommandLineOption configOption(QStringLiteral("config"),
        QStringLiteral("Override the v4 configuration file"), QStringLiteral("path"));
    parser.addOption(bridgeOption);
    parser.addOption(configOption);
    parser.process(application);

    RoleSelectionDialog roleDialog;
    if (roleDialog.exec() != QDialog::Accepted)
        return 0;
    SetupWindow window(std::make_unique<CliSetupStore>(
        parser.value(bridgeOption), parser.value(configOption)), roleDialog.role());
    window.show();
    return application.exec();
}
