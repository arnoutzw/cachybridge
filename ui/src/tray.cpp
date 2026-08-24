#include <QApplication>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QLocalSocket>
#include <QMenu>
#include <QProcess>
#include <QStandardPaths>

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
