#ifndef THEME_MANAGER_H
#define THEME_MANAGER_H

#include <QString>
#include <QColor>

enum ThemeMode {
    THEME_DARK,
    THEME_LIGHT,
    THEME_OLED
};

class ThemeManager {
public:
    static void applyTheme(ThemeMode mode, const QColor &accent = QColor(74, 124, 255));
    static QString getStyleSheet(ThemeMode mode, const QColor &accent);
};

#endif // THEME_MANAGER_H
