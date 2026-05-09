#include "menuwindow.h"
#include "mainwindow.h"
#include "includes.h"
#include "colours.h"
MenuWindow::MenuWindow(QWidget *parent) : QMainWindow(parent) {
    setupmenu();
}

void MenuWindow::setupmenu() {
    setWindowTitle("Obscuron Cryptographic Suite");
    setFixedSize(640, 420);

    // ── window palette ──
    QPalette winPal = palette();
    winPal.setColor(QPalette::Window,     QColor(COL_BG));
    winPal.setColor(QPalette::WindowText, QColor(COL_TEXT));
    winPal.setColor(QPalette::Base,       QColor(COL_SURFACE));
    winPal.setColor(QPalette::Text,       QColor(COL_TEXT));
    setPalette(winPal);
    setAutoFillBackground(true);
    QWidget *central = new QWidget(this);
    central->setAutoFillBackground(true);
    central->setPalette(winPal);
    QVBoxLayout *layout = new QVBoxLayout(central);
    layout->setContentsMargins(60, 50, 60, 50);
    layout->setSpacing(0);

    // ── title ──
    QLabel *title = new QLabel("OBSCURON");
    title->setAlignment(Qt::AlignHCenter);
    QFont titleFont("Courier New", 36, QFont::Bold);
    titleFont.setLetterSpacing(QFont::AbsoluteSpacing, 10);
    title->setFont(titleFont);
    QPalette titlePal = title->palette();
    titlePal.setColor(QPalette::WindowText, QColor(COL_ACCENT_GL));
    title->setPalette(titlePal);
    title->setAutoFillBackground(false);

    // ── subtitle ──
    QLabel *sub = new QLabel("cryptographic suite");
    sub->setAlignment(Qt::AlignHCenter);
    QFont subFont("Courier New", 12);
    subFont.setLetterSpacing(QFont::AbsoluteSpacing, 6);
    sub->setFont(subFont);
    QPalette subPal = sub->palette();
    subPal.setColor(QPalette::WindowText, QColor(COL_BORDER_HI));
    sub->setPalette(subPal);
    sub->setAutoFillBackground(false);

    // ── divider ──
    QFrame *line = new QFrame();
    line->setFrameShape(QFrame::HLine);
    line->setFrameShadow(QFrame::Plain);
    line->setFixedWidth(200);
    QPalette linePal = line->palette();
    linePal.setColor(QPalette::WindowText, QColor(COL_BORDER));
    line->setPalette(linePal);

    // ── button factory ──
    auto makeBtn = [&](const QString &text) -> QPushButton* {
        QPushButton *b = new QPushButton(text);
        b->setFixedWidth(320);
        b->setFixedHeight(46);
        b->setCursor(Qt::PointingHandCursor);
        b->setAutoFillBackground(true);
        b->setFlat(false);
        QFont btnFont("Courier New", 13);
        btnFont.setLetterSpacing(QFont::AbsoluteSpacing, 3);
        b->setFont(btnFont);
        QPalette btnPal = b->palette();
        btnPal.setColor(QPalette::Button,     QColor(COL_SURFACE));
        btnPal.setColor(QPalette::ButtonText, QColor(COL_TEXT_DIM));
        btnPal.setColor(QPalette::Window,     QColor(COL_SURFACE));
        b->setPalette(btnPal);
        return b;
    };

    btnCipher   = makeBtn("DECRYPT  | ENCRYPT");
    btnAnalyse  = makeBtn("ANALYSE");
    btnSettings = makeBtn("SETTINGS");
    // ── version tag ──
    QLabel *ver = new QLabel("v1.0  |  Obscuron");
    ver->setAlignment(Qt::AlignHCenter);
    QFont verFont("Courier New", 10);
    verFont.setLetterSpacing(QFont::AbsoluteSpacing, 3);
    ver->setFont(verFont);
    QPalette verPal = ver->palette();
    verPal.setColor(QPalette::WindowText, QColor(COL_BORDER));
    ver->setPalette(verPal);
    ver->setAutoFillBackground(false);
    // ── layout ──
    layout->addStretch(2);
    layout->addWidget(title);
    layout->addWidget(sub);
    layout->addSpacing(24);
    layout->addWidget(btnCipher,   0, Qt::AlignHCenter);
    layout->addSpacing(8);
    layout->addWidget(btnAnalyse,  0, Qt::AlignHCenter);
    layout->addSpacing(8);
    layout->addWidget(btnSettings, 0, Qt::AlignHCenter);
    layout->addStretch(1);
    layout->addWidget(ver);

    setCentralWidget(central);

    connect(btnCipher, &QPushButton::clicked, this, &MenuWindow::onCipherClicked);
}

void MenuWindow::onCipherClicked() {
    MainWindow *cyber = new MainWindow();
    cyber->show();
    this->hide();
}