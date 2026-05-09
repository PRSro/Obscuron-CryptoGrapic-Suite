#ifndef MENUWINDOW_H
#define MENUWINDOW_H

#include <QMainWindow>
#include <QPushButton>

class MenuWindow : public QMainWindow {
    Q_OBJECT
public:
    MenuWindow(QWidget *parent = nullptr);

private:
    QPushButton *btnCipher;
    QPushButton *btnAnalyse;
    QPushButton *btnSettings;

    void setupmenu();

private slots:
    void onCipherClicked();
};

#endif