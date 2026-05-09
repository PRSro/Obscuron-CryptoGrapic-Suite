#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "includes.h"

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow() {}

private:
    void setupcyberwindow();
    void setupsettingswindow();
    void setupanalysiswindow();
};

#endif