#include <QApplication>
#include <QButtonGroup>
#include <QCheckBox>
#include <QCommandLineParser>
#include <QFile>
#include <QFileInfo>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QSaveFile>
#include <QSysInfo>
#include <QTemporaryFile>
#include <QTemporaryDir>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <memory>

namespace {

enum class Placement { Left, Right, Above, Below };

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

class SetupStore {
public:
    virtual ~SetupStore() = default;
    virtual QString generatePairingToken(QString *error) = 0;
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
    explicit SetupWindow(std::unique_ptr<SetupStore> store) : store_(std::move(store)) {
        setWindowTitle(QStringLiteral("CachyBridge Setup"));
        setMinimumWidth(620);

        auto *heading = new QLabel(QStringLiteral("Pair two CachyOS desktops"));
        QFont headingFont = heading->font();
        headingFont.setPointSize(headingFont.pointSize() + 6);
        headingFont.setBold(true);
        heading->setFont(headingFont);

        auto *intro = new QLabel(QStringLiteral(
            "Choose where the client display sits relative to this host. "
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

        auto *placementBox = new QGroupBox(QStringLiteral("Client placement"));
        auto *placementGrid = new QGridLayout(placementBox);
        placementGroup_ = new QButtonGroup(this);
        placementGroup_->setExclusive(true);
        addPlacementButton(placementGrid, QStringLiteral("Client above\n↑"), Placement::Above, 0, 1);
        addPlacementButton(placementGrid, QStringLiteral("Client left\n←"), Placement::Left, 1, 0, true);
        auto *host = new QLabel(QStringLiteral("This host\n(center)"));
        host->setAlignment(Qt::AlignCenter);
        host->setMinimumSize(145, 72);
        host->setStyleSheet(QStringLiteral(
            "QLabel { border: 2px solid palette(highlight); border-radius: 8px; "
            "background: palette(base); font-weight: 600; }"));
        placementGrid->addWidget(host, 1, 1);
        addPlacementButton(placementGrid, QStringLiteral("Client right\n→"), Placement::Right, 1, 2);
        addPlacementButton(placementGrid, QStringLiteral("Client below\n↓"), Placement::Below, 2, 1);

        persistent_ = new QCheckBox(
            QStringLiteral("Remember desktop portal permissions (recommended on these two iMacs)"));
        persistent_->setToolTip(QStringLiteral(
            "Stores portal-issued single-use restore tokens in the private CachyBridge configuration."));

        auto *saveButton = new QPushButton(QStringLiteral("Save pairing"));
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
        layout->addLayout(form);
        layout->addWidget(placementBox);
        layout->addWidget(persistent_);
        layout->addLayout(actions);
    }

private:
    void addPlacementButton(QGridLayout *layout, const QString &label, Placement placement,
                            int row, int column, bool checked = false) {
        auto *button = new QPushButton(label);
        button->setCheckable(true);
        button->setMinimumSize(145, 72);
        button->setProperty("placement", placementName(placement));
        button->setChecked(checked);
        placementGroup_->addButton(button, static_cast<int>(placement));
        layout->addWidget(button, row, column);
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
        const auto *button = placementGroup_->checkedButton();
        if (!button)
            return;
        const auto placementText = button->property("placement").toString();
        Placement placement = Placement::Left;
        if (placementText == QStringLiteral("right")) placement = Placement::Right;
        else if (placementText == QStringLiteral("above")) placement = Placement::Above;
        else if (placementText == QStringLiteral("below")) placement = Placement::Below;

        SetupDraft draft{
            hostName_->text().trimmed(), hostEndpoint_->text().trimmed(),
            clientName_->text().trimmed(), clientEndpoint_->text().trimmed(),
            token, placement, persistent_->isChecked()
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
    QButtonGroup *placementGroup_ = nullptr;
    QCheckBox *persistent_ = nullptr;
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

    SetupWindow window(std::make_unique<CliSetupStore>(
        parser.value(bridgeOption), parser.value(configOption)));
    window.show();
    return application.exec();
}
