#include <QApplication>
#include "menuwindow.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    MenuWindow w;
    w.show();
    return app.exec();
}
