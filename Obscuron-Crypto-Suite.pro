QT += widgets

CONFIG += c++17

INCLUDEPATH += includes

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    main.cpp \
    mainwindow.cpp \
    menuwindow.cpp \
    src/basic_ciphers.cpp \
    src/historical_ciphers.cpp \
    src/essential_ciphers.cpp \
    src/bruteforce_ciphers.cpp \
    src/bytes.cpp \
    src/standard_ciphers.cpp

HEADERS += \
    colours.h \
    includes.h \
    mainwindow.h \
    menuwindow.h \
    includes/basic.h \
    includes/basic_ciphers.h \
    includes/historical_ciphers.h \
    includes/essential_ciphers.h \
    includes/bruteforce_ciphers.h \
    includes/bytes.h \
    includes/standard_ciphers.h

FORMS +=

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
