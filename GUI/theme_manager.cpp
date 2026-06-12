#include "theme_manager.h"
#include <QApplication>
#include <QPalette>

void ThemeManager::applyTheme(ThemeMode mode, const QColor &accent) {
    QString stylesheet = getStyleSheet(mode, accent);
    qApp->setStyleSheet(stylesheet);

    // Apply color palette variables if needed
    QPalette pal = qApp->palette();
    if (mode == THEME_LIGHT) {
        pal.setColor(QPalette::Window, QColor(245, 245, 247));
        pal.setColor(QPalette::WindowText, QColor(30, 30, 30));
        pal.setColor(QPalette::Base, QColor(255, 255, 255));
        pal.setColor(QPalette::Text, QColor(30, 30, 30));
        pal.setColor(QPalette::Button, QColor(235, 235, 240));
        pal.setColor(QPalette::ButtonText, QColor(30, 30, 30));
    } else {
        QColor bg = (mode == THEME_OLED) ? QColor(0, 0, 0) : QColor(10, 5, 20);
        QColor surf = (mode == THEME_OLED) ? QColor(10, 10, 10) : QColor(18, 10, 32);
        pal.setColor(QPalette::Window, bg);
        pal.setColor(QPalette::WindowText, QColor(224, 224, 240));
        pal.setColor(QPalette::Base, surf);
        pal.setColor(QPalette::Text, QColor(224, 224, 240));
        pal.setColor(QPalette::Button, surf);
        pal.setColor(QPalette::ButtonText, QColor(224, 224, 240));
    }
    qApp->setPalette(pal);
}

QString ThemeManager::getStyleSheet(ThemeMode mode, const QColor &accent) {
    QString hexAccent = accent.name();
    QString hexGlow = accent.lighter(130).name();

    QString bg, surf, surf2, border, text, text_dim, scrollBg, scrollHandle;

    if (mode == THEME_LIGHT) {
        bg = "#f5f5f7";
        surf = "#ffffff";
        surf2 = "#f0f0f5";
        border = "#d2d2d7";
        text = "#1d1d1f";
        text_dim = "#86868b";
        scrollBg = "#f5f5f7";
        scrollHandle = "#c1c1c7";
    } else if (mode == THEME_OLED) {
        bg = "#000000";
        surf = "#0c0c0c";
        surf2 = "#141414";
        border = "#1a1a1a";
        text = "#e8e6f0";
        text_dim = "#7a7898";
        scrollBg = "#080808";
        scrollHandle = "#2c2c2c";
    } else { // THEME_DARK - violet-blue-green palette
        bg = "#0a0514";
        surf = "#120a20";
        surf2 = "#1a1030";
        border = "#1e1850";
        text = "#e0e0f0";
        text_dim = "#8880a0";
        scrollBg = "#0a0514";
        scrollHandle = "#1e1850";
    }

    return QString(
        "QMainWindow { background: %1; }"
        "QWidget { color: %5; font-family: 'Courier New', monospace; }"
        "QPlainTextEdit, QLineEdit { background: %2; color: %5; border: 1px solid %4; "
        "  border-radius: 6px; padding: 8px; font-family: 'Courier New', monospace; font-size: 12px; }"
        "QPlainTextEdit:focus, QLineEdit:focus { border: 1px solid %6; }"
        "QComboBox { background: %2; color: %5; border: 1px solid %4; "
        "  border-radius: 6px; padding: 4px 12px; min-height: 28px; font-family: 'Courier New', monospace; }"
        "QComboBox:focus { border: 1px solid %6; }"
        "QComboBox::drop-down { border: none; width: 24px; }"
        "QComboBox QAbstractItemView { background: %2; color: %5; "
        "  selection-background-color: %6; border: 1px solid %4; }"
        "QSpinBox { background: %2; color: %5; border: 1px solid %4; "
        "  border-radius: 6px; padding: 4px; min-height: 26px; }"
        "QSpinBox:focus { border: 1px solid %6; }"
        "QPushButton { background: %3; color: %5; border: 1px solid %4; "
        "  border-radius: 6px; padding: 8px 18px; font-family: 'Courier New', monospace; font-weight: bold; }"
        "QPushButton:hover { border: 1px solid %6; color: %7; background: %2; }"
        "QPushButton:pressed { background: %6; color: #ffffff; }"
        "QListWidget { background: %2; color: %5; border: 1px solid %4; "
        "  border-radius: 6px; font-family: 'Courier New', monospace; font-size: 12px; padding: 4px; }"
        "QListWidget::item { padding: 6px; border-radius: 4px; }"
        "QListWidget::item:hover { background: %3; }"
        "QListWidget::item:selected { background: %6; color: #ffffff; }"
        "QLabel { color: %5; font-family: 'Courier New', monospace; }"
        "QGroupBox { border: 1px solid %4; border-radius: 8px; margin-top: 14px; "
        "  padding-top: 16px; font-family: 'Courier New', monospace; font-weight: bold; color: %7; }"
        "QGroupBox::title { subcontrol-origin: margin; left: 14px; padding: 0 6px; }"
        "QTabWidget::pane { border: 1px solid %4; background: %2; border-radius: 6px; top: -1px; }"
        "QTabBar::tab { background: %3; border: 1px solid %4; border-bottom: none; "
        "  border-top-left-radius: 6px; border-top-right-radius: 6px; padding: 8px 16px; margin-right: 2px; }"
        "QTabBar::tab:selected { background: %2; border-bottom: 1px solid %2; color: %7; font-weight: bold; }"
        "QTabBar::tab:hover { background: %2; }"
        "QScrollBar:vertical { background: %8; width: 10px; margin: 0px; }"
        "QScrollBar::handle:vertical { background: %9; min-height: 20px; border-radius: 5px; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }"
        "QScrollBar:horizontal { background: %8; height: 10px; margin: 0px; }"
        "QScrollBar::handle:horizontal { background: %9; min-width: 20px; border-radius: 5px; }"
        "QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0px; }"
        "QSplitter::handle { background: %4; }"
    )
    .arg(bg)          // %1
    .arg(surf)        // %2
    .arg(surf2)       // %3
    .arg(border)      // %4
    .arg(text)        // %5
    .arg(hexAccent)   // %6
    .arg(hexGlow)     // %7
    .arg(scrollBg)    // %8
    .arg(scrollHandle)// %9
    ;
}
