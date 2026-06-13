#ifndef NUMBERWINDOW_H
#define NUMBERWINDOW_H

#include <QMainWindow>
#include <QPlainTextEdit>
#include <QComboBox>
#include <QSpinBox>
#include <QPushButton>
#include <QLabel>

class NumberWindow : public QMainWindow {
    Q_OBJECT
public:
    NumberWindow(QWidget *parent = nullptr);
    ~NumberWindow() = default;

private:
    QPlainTextEdit *inputArea;
    QPlainTextEdit *outputArea;
    QComboBox *operationCombo;
    QComboBox *typeCombo;
    QSpinBox *baseSpin;
    QLabel *baseLabel;
    QPushButton *runBtn;
    QPushButton *backBtn;
    QPushButton *advancedBtn;

    QPlainTextEdit *detectOutput;
    QPushButton *detectBtn;
    QPushButton *attackBtn;

    void setupUI();

private slots:
    void onRun();
    void onTypeChanged(int index);
    void onAdvanced();
    void onDetect();
    void onAttack();
};

#endif
