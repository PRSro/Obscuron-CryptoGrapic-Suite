#ifndef VISUALIZER_WIDGETS_H
#define VISUALIZER_WIDGETS_H

#include <QWidget>
#include <string>
#include <vector>

// 1. Character Frequency Histogram comparing current text with standard English
class FrequencyHistogram : public QWidget {
    Q_OBJECT
public:
    explicit FrequencyHistogram(QWidget *parent = nullptr);
    void setData(const std::string &data);

protected:
    void paintEvent(QPaintEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;

private:
    std::vector<double> m_freqs;      // Current data letter frequencies (A-Z)
    std::vector<double> m_english;    // Standard English frequencies (A-Z)
    int m_hover_index = -1;
};

// 2. Entropy Heatmap to visualize byte randomness
class EntropyHeatmap : public QWidget {
    Q_OBJECT
public:
    explicit EntropyHeatmap(QWidget *parent = nullptr);
    void setData(const std::string &data);

protected:
    void paintEvent(QPaintEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;

private:
    std::vector<double> m_block_entropy; // Shannon entropy for each data block
    int m_hover_x = -1;
    int m_hover_y = -1;
};

// 3. Shannon Entropy Graph: smooth line chart showing entropy over sliding window
class ShannonEntropyGraph : public QWidget {
    Q_OBJECT
public:
    explicit ShannonEntropyGraph(QWidget *parent = nullptr);
    void setData(const std::string &data);

protected:
    void paintEvent(QPaintEvent *event) override;

private:
    std::vector<double> m_rolling_entropy;
};

// 4. Interactive Encoding Wheel showing radix conversion
class EncodingWheel : public QWidget {
    Q_OBJECT
public:
    explicit EncodingWheel(QWidget *parent = nullptr);
    void setValue(const std::string &input_text);

signals:
    void baseSelected(int radix);

protected:
    void paintEvent(QPaintEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;

private:
    std::string m_binary;
    std::string m_octal;
    std::string m_decimal;
    std::string m_hex;
    std::string m_base64;
    int m_selected_wheel_sector = -1;
};

#endif // VISUALIZER_WIDGETS_H
