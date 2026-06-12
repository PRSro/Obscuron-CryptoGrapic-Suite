#include "visualizer_widgets.h"
#include "colours.h"
#include <QPainter>
#include <QMouseEvent>
#include <QPainterPath>
#include <cmath>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include "modern_ciphers.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif


// Standard English Letter Frequencies (A-Z)

static const double ENG_FREQ[26] = {
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094,
    6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929,
    0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150,
    1.974, 0.074
};

// Helper to calculate Shannon entropy
static double calc_entropy(const uint8_t *data, size_t len) {
    if (len == 0) return 0.0;
    size_t counts[256] = {0};
    for (size_t i = 0; i < len; ++i) counts[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (counts[i] == 0) continue;
        double p = (double)counts[i] / len;
        entropy -= p * log2(p);
    }
    return entropy;
}

// ─────────────────────────────────────────────────────────────────────────────
// FrequencyHistogram Widget
// ─────────────────────────────────────────────────────────────────────────────

FrequencyHistogram::FrequencyHistogram(QWidget *parent) : QWidget(parent) {
    setMouseTracking(true);
    m_freqs.resize(26, 0.0);
    m_english.assign(ENG_FREQ, ENG_FREQ + 26);
    setMinimumHeight(160);
}

void FrequencyHistogram::setData(const std::string &data) {
    m_freqs.assign(26, 0.0);
    size_t letters_count = 0;
    for (unsigned char c : data) {
        if (c >= 'A' && c <= 'Z') {
            m_freqs[c - 'A'] += 1.0;
            letters_count++;
        } else if (c >= 'a' && c <= 'z') {
            m_freqs[c - 'a'] += 1.0;
            letters_count++;
        }
    }
    if (letters_count > 0) {
        for (int i = 0; i < 26; ++i) {
            m_freqs[i] = (m_freqs[i] * 100.0) / letters_count;
        }
    }
    update();
}

void FrequencyHistogram::paintEvent(QPaintEvent *event) {
    Q_UNUSED(event);
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);

    // Draw dark background
    painter.fillRect(rect(), COL_SURFACE);

    int w = width();
    int h = height();
    int padding = 24;
    int chart_h = h - 2 * padding;
    int col_w = (w - 2 * padding) / 26;

    // Find max frequency to scale the chart
    double max_freq = 15.0; // default cap
    for (double f : m_freqs) if (f > max_freq) max_freq = f;

    // Draw thin gridlines
    painter.setPen(QPen(COL_BORDER, 1, Qt::DashLine));
    for (int y = 1; y <= 3; ++y) {
        int y_pos = padding + chart_h - (y * chart_h / 4);
        painter.drawLine(padding, y_pos, w - padding, y_pos);
        painter.drawText(padding - 20, y_pos + 4, QString::number(y * (int)max_freq / 4) + "%");
    }

    // Draw bars
    for (int i = 0; i < 26; ++i) {
        int x = padding + i * col_w;
        int bar_gap = 2;
        int bar_w = (col_w - bar_gap * 2) / 2;

        // English standard bar (translucent accent color)
        double eng_f = m_english[i];
        int eng_h = (eng_f / max_freq) * chart_h;
        int eng_y = padding + chart_h - eng_h;
        painter.fillRect(x + bar_gap, eng_y, bar_w, eng_h, QColor(COL_ACCENT.red(), COL_ACCENT.green(), COL_ACCENT.blue(), 100));

        // Data frequency bar (teal color)
        double dat_f = m_freqs[i];
        int dat_h = (dat_f / max_freq) * chart_h;
        int dat_y = padding + chart_h - dat_h;
        painter.fillRect(x + bar_gap + bar_w, dat_y, bar_w, dat_h, COL_OUTPUT);

        // Hover highlight
        if (i == m_hover_index) {
            painter.fillRect(x, padding, col_w, chart_h, QColor(255, 255, 255, 25));
        }

        // Draw bottom label
        painter.setPen(COL_TEXT_DIM);
        painter.setFont(QFont("Courier New", 8, QFont::Bold));
        painter.drawText(x + col_w / 4, h - padding + 12, QString((char)('A' + i)));
    }

    // Draw Tooltip
    if (m_hover_index >= 0 && m_hover_index < 26) {
        QString tip = QString("%1: Data %2% | English %3%")
                          .arg((char)('A' + m_hover_index))
                          .arg(m_freqs[m_hover_index], 0, 'f', 1)
                          .arg(m_english[m_hover_index], 0, 'f', 1);

        painter.setPen(COL_ACCENT_GL);
        painter.setBrush(COL_SURFACE2);
        int tip_w = 210;
        int tip_h = 24;
        int tip_x = std::clamp(padding + m_hover_index * col_w - tip_w / 2, 4, w - tip_w - 4);
        int tip_y = padding - 4;
        
        painter.drawRoundedRect(tip_x, tip_y, tip_w, tip_h, 4, 4);
        painter.setPen(COL_TEXT);
        painter.setFont(QFont("Courier New", 9));
        painter.drawText(tip_x + 6, tip_y + 16, tip);
    }
}

void FrequencyHistogram::mouseMoveEvent(QMouseEvent *event) {
    int padding = 24;
    int col_w = (width() - 2 * padding) / 26;
    if (col_w <= 0) return;
    int idx = (static_cast<int>(event->position().x()) - padding) / col_w;
    if (idx >= 0 && idx < 26) {
        if (idx != m_hover_index) {
            m_hover_index = idx;
            update();
        }
    } else {
        if (m_hover_index != -1) {
            m_hover_index = -1;
            update();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EntropyHeatmap Widget
// ─────────────────────────────────────────────────────────────────────────────

EntropyHeatmap::EntropyHeatmap(QWidget *parent) : QWidget(parent) {
    setMouseTracking(true);
    setMinimumHeight(150);
}

void EntropyHeatmap::setData(const std::string &data) {
    m_block_entropy.clear();
    if (data.empty()) {
        update();
        return;
    }

    // Determine optimal block size (e.g. 16 or 32 bytes)
    size_t block_size = 16;
    if (data.size() > 1024) block_size = 64;
    if (data.size() > 8192) block_size = 256;

    for (size_t i = 0; i < data.size(); i += block_size) {
        size_t len = std::min(block_size, data.size() - i);
        double e = calc_entropy((const uint8_t*)data.data() + i, len);
        m_block_entropy.push_back(e);
        if (m_block_entropy.size() >= 256) break; // cap at 256 grid blocks
    }
    update();
}

void EntropyHeatmap::paintEvent(QPaintEvent *event) {
    Q_UNUSED(event);
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);

    painter.fillRect(rect(), COL_SURFACE);

    if (m_block_entropy.empty()) {
        painter.setPen(COL_TEXT_DIM);
        painter.drawText(rect(), Qt::AlignCenter, "No analysis data");
        return;
    }

    int n = (int)m_block_entropy.size();
    int cols = std::ceil(std::sqrt(n));
    if (cols < 4) cols = 4;
    int rows = (n + cols - 1) / cols;

    int cell_w = (width() - 10) / cols;
    int cell_h = (height() - 10) / rows;
    if (cell_w <= 0) cell_w = 4;
    if (cell_h <= 0) cell_h = 4;

    for (int i = 0; i < n; ++i) {
        int r = i / cols;
        int c = i % cols;
        int x = 5 + c * cell_w;
        int y = 5 + r * cell_h;

        double ent = m_block_entropy[i];
        // Scale to 0.0 - 8.0 max Shannon entropy
        double ratio = ent / 8.0;
        if (ratio > 1.0) ratio = 1.0;

        // Mix custom colors: Low (dark slate/purple) -> High (bright teal output color)
        int r_val = COL_SURFACE.red() + (COL_OUTPUT.red() - COL_SURFACE.red()) * ratio;
        int g_val = COL_SURFACE.green() + (COL_OUTPUT.green() - COL_SURFACE.green()) * ratio;
        int b_val = COL_SURFACE.blue() + (COL_OUTPUT.blue() - COL_SURFACE.blue()) * ratio;
        QColor color(r_val, g_val, b_val);

        painter.fillRect(x + 1, y + 1, cell_w - 2, cell_h - 2, color);

        // Highlights for hover
        if (c == m_hover_x && r == m_hover_y) {
            painter.setPen(QPen(COL_TEXT, 2));
            painter.drawRect(x, y, cell_w - 1, cell_h - 1);
        }
    }

    // Display hover value info
    if (m_hover_x >= 0 && m_hover_y >= 0) {
        int idx = m_hover_y * cols + m_hover_x;
        if (idx >= 0 && idx < n) {
            double ent = m_block_entropy[idx];
            QString msg = QString("Block #%1: Entropy %2").arg(idx + 1).arg(ent, 0, 'f', 2);
            painter.setPen(COL_ACCENT_GL);
            painter.fillRect(5, height() - 22, 180, 18, COL_SURFACE2);
            painter.drawText(8, height() - 8, msg);
        }
    }
}

void EntropyHeatmap::mouseMoveEvent(QMouseEvent *event) {
    if (m_block_entropy.empty()) return;
    int n = (int)m_block_entropy.size();
    int cols = std::ceil(std::sqrt(n));
    if (cols < 4) cols = 4;
    int rows = (n + cols - 1) / cols;

    int cell_w = (width() - 10) / cols;
    int cell_h = (height() - 10) / rows;
    if (cell_w <= 0 || cell_h <= 0) return;

    int cx = (static_cast<int>(event->position().x()) - 5) / cell_w;
    int cy = (static_cast<int>(event->position().y()) - 5) / cell_h;

    if (cx >= 0 && cx < cols && cy >= 0 && cy < rows && (cy * cols + cx) < n) {
        if (cx != m_hover_x || cy != m_hover_y) {
            m_hover_x = cx;
            m_hover_y = cy;
            update();
        }
    } else {
        if (m_hover_x != -1 || m_hover_y != -1) {
            m_hover_x = -1;
            m_hover_y = -1;
            update();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ShannonEntropyGraph Widget
// ─────────────────────────────────────────────────────────────────────────────

ShannonEntropyGraph::ShannonEntropyGraph(QWidget *parent) : QWidget(parent) {
    setMinimumHeight(150);
}

void ShannonEntropyGraph::setData(const std::string &data) {
    m_rolling_entropy.clear();
    if (data.size() < 16) {
        update();
        return;
    }

    size_t win_sz = 16;
    if (data.size() > 500) win_sz = 64;
    size_t step = std::max((size_t)1, data.size() / 100); // sample about 100 points

    for (size_t i = 0; i + win_sz <= data.size(); i += step) {
        double ent = calc_entropy((const uint8_t*)data.data() + i, win_sz);
        m_rolling_entropy.push_back(ent);
    }
    update();
}

void ShannonEntropyGraph::paintEvent(QPaintEvent *event) {
    Q_UNUSED(event);
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);

    painter.fillRect(rect(), COL_SURFACE);

    if (m_rolling_entropy.size() < 2) {
        painter.setPen(COL_TEXT_DIM);
        painter.drawText(rect(), Qt::AlignCenter, "Insufficient data for rolling graph");
        return;
    }

    int w = width();
    int h = height();
    int pad = 20;

    int graph_w = w - 2 * pad;
    int graph_h = h - 2 * pad;

    // Draw Grid Lines (from 0.0 to 8.0 bits)
    painter.setPen(QPen(COL_BORDER, 1, Qt::DotLine));
    for (int i = 0; i <= 4; ++i) {
        int y = pad + graph_h - (i * graph_h / 4);
        painter.drawLine(pad, y, w - pad, y);
        painter.setPen(COL_TEXT_DIM);
        painter.drawText(2, y + 4, QString::number(i * 2));
    }

    // Build the line path
    QPainterPath path;
    double step_x = (double)graph_w / (m_rolling_entropy.size() - 1);
    
    for (size_t i = 0; i < m_rolling_entropy.size(); ++i) {
        double ent = m_rolling_entropy[i];
        double x = pad + i * step_x;
        double y = pad + graph_h - (ent / 8.0 * graph_h);
        if (i == 0) path.moveTo(x, y);
        else path.lineTo(x, y);
    }

    // Fill area under curve
    QPainterPath areaPath = path;
    areaPath.lineTo(pad + graph_w, pad + graph_h);
    areaPath.lineTo(pad, pad + graph_h);
    areaPath.closeSubpath();

    QLinearGradient areaGrad(0, pad, 0, pad + graph_h);
    areaGrad.setColorAt(0, QColor(COL_ACCENT.red(), COL_ACCENT.green(), COL_ACCENT.blue(), 100));
    areaGrad.setColorAt(1, QColor(COL_ACCENT.red(), COL_ACCENT.green(), COL_ACCENT.blue(), 0));
    painter.fillPath(areaPath, areaGrad);

    // Draw main line
    painter.setPen(QPen(COL_ACCENT_HI, 2));
    painter.drawPath(path);
}

// ─────────────────────────────────────────────────────────────────────────────
// EncodingWheel Widget
// ─────────────────────────────────────────────────────────────────────────────

EncodingWheel::EncodingWheel(QWidget *parent) : QWidget(parent) {
    setMinimumSize(220, 220);
}

void EncodingWheel::setValue(const std::string &input_text) {
    m_binary.clear();
    m_octal.clear();
    m_decimal.clear();
    m_hex.clear();
    m_base64.clear();

    if (input_text.empty()) {
        update();
        return;
    }

    // Take first 4 bytes of input text to perform visual conversion wheel
    uint64_t val = 0;
    for (size_t i = 0; i < std::min((size_t)4, input_text.size()); ++i) {
        val = (val << 8) | (unsigned char)input_text[i];
    }

    // Create string representations
    std::stringstream ss;
    // 1. Binary
    for (int i = 31; i >= 0; i--) ss << ((val >> i) & 1);
    m_binary = ss.str().substr(0, 16) + "...";
    
    // 2. Octal
    ss.str(""); ss << std::oct << val;
    m_octal = ss.str();

    // 3. Decimal
    ss.str(""); ss << val;
    m_decimal = ss.str();

    // 4. Hex
    ss.str(""); ss << std::hex << std::uppercase << val;
    m_hex = "0x" + ss.str();

    // 5. Base64
    m_base64 = base64url_encode(input_text.substr(0, std::min((size_t)8, input_text.size())));
    if (m_base64.size() > 8) m_base64 = m_base64.substr(0, 8) + "..";

    update();
}

void EncodingWheel::paintEvent(QPaintEvent *event) {
    Q_UNUSED(event);
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);

    painter.fillRect(rect(), COL_SURFACE);

    int w = width();
    int h = height();
    int cx = w / 2;
    int cy = h / 2;
    int radius = std::min(cx, cy) - 20;

    // Draw concentric rings
    painter.setPen(QPen(COL_BORDER, 2));
    painter.drawEllipse(cx - radius, cy - radius, radius * 2, radius * 2);
    painter.drawEllipse(cx - radius / 2, cy - radius / 2, radius, radius);

    // Draw division lines (5 sectors)
    painter.setPen(QPen(COL_BORDER_HI, 1));
    for (int i = 0; i < 5; ++i) {
        double angle = i * 2.0 * M_PI / 5.0 - M_PI / 2.0;
        painter.drawLine(cx, cy, cx + radius * cos(angle), cy + radius * sin(angle));
    }

    // Draw text values in sectors
    QString labels[5] = {"BIN", "OCT", "DEC", "HEX", "B64"};
    QString values[5] = {
        QString::fromStdString(m_binary),
        QString::fromStdString(m_octal),
        QString::fromStdString(m_decimal),
        QString::fromStdString(m_hex),
        QString::fromStdString(m_base64)
    };

    for (int i = 0; i < 5; ++i) {
        double mid_angle = (i + 0.5) * 2.0 * M_PI / 5.0 - M_PI / 2.0;
        int text_r = radius * 0.7;
        int tx = cx + text_r * cos(mid_angle);
        int ty = cy + text_r * sin(mid_angle);

        // Draw Sector Label
        painter.setPen(COL_ACCENT_GL);
        painter.setFont(QFont("Courier New", 9, QFont::Bold));
        painter.drawText(tx - 15, ty - 6, labels[i]);

        // Draw Value
        painter.setPen(COL_TEXT);
        painter.setFont(QFont("Courier New", 8));
        QString val = values[i].isEmpty() ? "---" : values[i];
        if (val.size() > 10) val = val.left(8) + "..";
        painter.drawText(tx - 24, ty + 8, val);

        // Highlight selected
        if (i == m_selected_wheel_sector) {
            painter.setPen(QPen(COL_OUTPUT, 2));
            painter.drawEllipse(tx - 30, ty - 15, 60, 30);
        }
    }

    // Center Hub
    painter.setBrush(COL_BG);
    painter.setPen(QPen(COL_OUTPUT, 2));
    painter.drawEllipse(cx - 24, cy - 24, 48, 48);
    painter.setPen(COL_OUTPUT);
    painter.drawText(cx - 14, cy + 5, "CORE");
}

void EncodingWheel::mousePressEvent(QMouseEvent *event) {
    int cx = width() / 2;
    int cy = height() / 2;
    int dx = static_cast<int>(event->position().x()) - cx;
    int dy = static_cast<int>(event->position().y()) - cy;
    double dist = sqrt(dx*dx + dy*dy);
    int radius = std::min(cx, cy) - 20;

    if (dist > 24 && dist < radius) {
        double angle = atan2(dy, dx) + M_PI / 2.0;
        if (angle < 0) angle += 2.0 * M_PI;
        int sector = (int)(angle / (2.0 * M_PI / 5.0)) % 5;
        m_selected_wheel_sector = sector;

        int radices[5] = {2, 8, 10, 16, 64};
        emit baseSelected(radices[sector]);
        update();
    }
}
