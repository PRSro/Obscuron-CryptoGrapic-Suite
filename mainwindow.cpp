#include "mainwindow.h"

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    setupcyberwindow();
}

void MainWindow::setupcyberwindow() {
    setWindowTitle("Obscuron — Cipher Suite");
    setMinimumSize(900, 600);
    setStyleSheet("QMainWindow, QWidget { background:#080810; color:#e6edf3; }");

    QWidget *central = new QWidget(this);
    QVBoxLayout *layout = new QVBoxLayout(central);

    QLabel *label = new QLabel("Cipher window — build here");
    label->setAlignment(Qt::AlignCenter);
    label->setStyleSheet("color:#00e5ff; font-size:18px; font-family:'Courier New',monospace;");

    layout->addWidget(label);
    setCentralWidget(central);
}

void MainWindow::setupsettingswindow() {}
void MainWindow::setupanalysiswindow() {}