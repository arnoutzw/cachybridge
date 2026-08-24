#include <QApplication>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QMenu>
#include <QProcess>
#include <QStandardPaths>

#include <KStatusNotifierItem>

namespace {

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
        menu->addAction(QStringLiteral("Quit CachyBridge"), &application_,
            &QCoreApplication::quit);
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
