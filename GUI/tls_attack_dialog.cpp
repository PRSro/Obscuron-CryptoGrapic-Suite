#include "tls_attack_dialog.h"
#include "theme_manager.h"
#include "colours.h"
#include "modern_ciphers.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QFont>
#include <QApplication>
#include <QClipboard>
#include <QScrollArea>
#include <QDateTime>
#include <QTimeZone>
#include <sstream>

TlsAttackDialog::TlsAttackDialog(QWidget *parent) : QDialog(parent) {
    setWindowTitle("TLS/SSL Attack Panel");
    setMinimumSize(800, 700);
    resize(900, 750);
    setStyleSheet(
        "QDialog, QWidget { background:#0a0514; color:#e0e0f0; }"
        "QPlainTextEdit, QLineEdit { background:#120a20; color:#e0e0f0; border:1px solid #1e1850;"
        "  border-radius:4px; padding:6px; font-family:'Courier New',monospace; font-size:12px; }"
        "QPlainTextEdit:focus, QLineEdit:focus { border:1px solid #4a7cff; }"
        "QComboBox { background:#120a20; color:#e0e0f0; border:1px solid #1e1850;"
        "  border-radius:4px; padding:4px 8px; min-height:28px; }"
        "QComboBox:hover { border:1px solid #4a7cff; }"
        "QComboBox QAbstractItemView { background:#120a20; color:#e0e0f0; selection-background-color:#2a2270; }"
        "QPushButton { background:#1a1030; color:#e0e0f0; border:1px solid #2a2270;"
        "  border-radius:4px; padding:8px 16px; font-weight:bold; }"
        "QPushButton:hover { background:#2a2270; border:1px solid #4a7cff; }"
        "QCheckBox { color:#e0e0f0; spacing:6px; }"
        "QCheckBox::indicator { width:16px; height:16px; background:#120a20; border:1px solid #1e1850; border-radius:3px; }"
        "QCheckBox::indicator:checked { background:#4a7cff; }"
        "QListWidget { background:#120a20; color:#e0e0f0; border:1px solid #1e1850; border-radius:4px; }"
        "QTreeWidget { background:#120a20; color:#e0e0f0; border:1px solid #1e1850; border-radius:4px; }"
        "QTreeWidget::item { padding:4px; }"
        "QTreeWidget::item:selected { background:#2a2270; }"
        "QHeaderView::section { background:#1a1030; color:#e0e0f0; border:1px solid #1e1850; padding:4px; }"
        "QTabWidget::pane { background:#0a0514; border:1px solid #1e1850; }"
        "QTabBar::tab { background:#1a1030; color:#8880a0; border:1px solid #1e1850;"
        "  padding:8px 16px; margin-right:2px; border-top-left-radius:4px; border-top-right-radius:4px; }"
        "QTabBar::tab:selected { background:#0a0514; color:#e0e0f0; border-bottom:2px solid #4a7cff; }"
    );

    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(10, 10, 10, 10);

    m_tabs = new QTabWidget();
    mainLayout->addWidget(m_tabs);

    QWidget *fpTab = new QWidget();
    setupFingerprintTab(fpTab);
    m_tabs->addTab(fpTab, "Fingerprint");

    QWidget *sdTab = new QWidget();
    setupSessionDecryptTab(sdTab);
    m_tabs->addTab(sdTab, "Session Decrypt");

    QWidget *certTab = new QWidget();
    setupCertParserTab(certTab);
    m_tabs->addTab(certTab, "Certificate Parser");
}

void TlsAttackDialog::setupFingerprintTab(QWidget *tab) {
    QVBoxLayout *lay = new QVBoxLayout(tab);
    lay->setContentsMargins(8, 8, 8, 8);
    lay->setSpacing(6);

    m_fpInput = new QPlainTextEdit();
    m_fpInput->setPlaceholderText("Paste raw bytes, hex dump, PEM text, or pcap path...");
    m_fpInput->setMinimumHeight(100);
    lay->addWidget(new QLabel("Input:"));
    lay->addWidget(m_fpInput);

    QHBoxLayout *ctrlRow = new QHBoxLayout();
    m_fpAuto = new QCheckBox("Auto-detect on change");
    ctrlRow->addWidget(m_fpAuto);
    ctrlRow->addStretch();
    m_fpAnalyse = new QPushButton("Analyse");
    m_fpAnalyse->setStyleSheet("background:#4a7cff; color:#fff; font-weight:bold;");
    ctrlRow->addWidget(m_fpAnalyse);
    lay->addLayout(ctrlRow);

    m_fpOutput = new QPlainTextEdit();
    m_fpOutput->setReadOnly(true);
    m_fpOutput->setMinimumHeight(120);
    QFont mono("Courier New", 11);
    m_fpOutput->setFont(mono);
    lay->addWidget(new QLabel("Analysis:"));
    lay->addWidget(m_fpOutput);

    m_fpIssues = new QListWidget();
    m_fpIssues->setMinimumHeight(80);
    m_fpIssues->setMaximumHeight(140);
    lay->addWidget(new QLabel("Detected Issues:"));
    lay->addWidget(m_fpIssues);

    connect(m_fpAnalyse, &QPushButton::clicked, this, &TlsAttackDialog::onAnalyse);
    if (m_fpAuto) {
        connect(m_fpInput, &QPlainTextEdit::textChanged, this, [this]() {
            if (m_fpAuto->isChecked() && !m_fpInput->toPlainText().trimmed().isEmpty())
                onAnalyse();
        });
    }
}

void TlsAttackDialog::setupSessionDecryptTab(QWidget *tab) {
    QVBoxLayout *lay = new QVBoxLayout(tab);
    lay->setContentsMargins(8, 8, 8, 8);
    lay->setSpacing(6);

    m_sdInput = new QPlainTextEdit();
    m_sdInput->setPlaceholderText("Paste pcap hex dump or raw TLS record bytes...");
    m_sdInput->setMinimumHeight(100);
    lay->addWidget(new QLabel("TLS Record / pcap:"));
    lay->addWidget(m_sdInput);

    m_sdKey = new QLineEdit();
    m_sdKey->setPlaceholderText("Private key (PEM text or hex modulus)");
    lay->addWidget(new QLabel("Private Key:"));
    lay->addWidget(m_sdKey);

    QHBoxLayout *paramRow = new QHBoxLayout();
    paramRow->addWidget(new QLabel("TLS Version:"));
    m_sdVersion = new QComboBox();
    m_sdVersion->addItems({"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"});
    paramRow->addWidget(m_sdVersion);
    paramRow->addWidget(new QLabel("Cipher:"));
    m_sdCipher = new QComboBox();
    m_sdCipher->addItems({"AES-128-CBC", "AES-256-CBC", "AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305"});
    paramRow->addWidget(m_sdCipher);
    paramRow->addStretch();
    lay->addLayout(paramRow);

    m_sdDecrypt = new QPushButton("Decrypt Session");
    m_sdDecrypt->setStyleSheet("background:#006644; color:#fff; font-weight:bold;");
    lay->addWidget(m_sdDecrypt);

    m_sdOutput = new QPlainTextEdit();
    m_sdOutput->setReadOnly(true);
    m_sdOutput->setMinimumHeight(150);
    m_sdOutput->setFont(QFont("Courier New", 11));
    lay->addWidget(new QLabel("Decrypted Data:"));
    lay->addWidget(m_sdOutput);

    connect(m_sdDecrypt, &QPushButton::clicked, this, &TlsAttackDialog::onDecrypt);
}

void TlsAttackDialog::setupCertParserTab(QWidget *tab) {
    QVBoxLayout *lay = new QVBoxLayout(tab);
    lay->setContentsMargins(8, 8, 8, 8);
    lay->setSpacing(6);

    m_certInput = new QPlainTextEdit();
    m_certInput->setPlaceholderText("Paste PEM certificate, hex DER, or raw DER bytes...");
    m_certInput->setMinimumHeight(80);
    lay->addWidget(new QLabel("Certificate Input:"));
    lay->addWidget(m_certInput);

    m_certParse = new QPushButton("Parse Certificate");
    m_certParse->setStyleSheet("background:#4a7cff; color:#fff; font-weight:bold;");
    lay->addWidget(m_certParse);

    m_certTree = new QTreeWidget();
    m_certTree->setHeaderLabels({"Field", "Value"});
    m_certTree->setAlternatingRowColors(false);
    m_certTree->setRootIsDecorated(false);
    m_certTree->setMinimumHeight(200);
    lay->addWidget(m_certTree);

    QHBoxLayout *btnRow = new QHBoxLayout();
    m_certExtractRsa = new QPushButton("Extract Public Key  RSA Attack");
    m_certExtractRsa->setStyleSheet("background:#aa5500; color:#fff; font-weight:bold;");
    btnRow->addWidget(m_certExtractRsa);

    m_certCheckExpiry = new QPushButton("Check Expiry");
    m_certCheckExpiry->setStyleSheet("background:#006644; color:#fff; font-weight:bold;");
    btnRow->addWidget(m_certCheckExpiry);
    btnRow->addStretch();
    lay->addLayout(btnRow);

    connect(m_certParse, &QPushButton::clicked, this, &TlsAttackDialog::onParseCert);
    connect(m_certExtractRsa, &QPushButton::clicked, this, &TlsAttackDialog::onExtractRsa);
    connect(m_certCheckExpiry, &QPushButton::clicked, this, &TlsAttackDialog::onCheckExpiry);
}

void TlsAttackDialog::onAnalyse() {
    m_fpOutput->clear();
    m_fpIssues->clear();
    std::string input = m_fpInput->toPlainText().toStdString();
    if (input.empty()) return;

    TlsFingerprint fp = tls_fingerprint(input);

    std::ostringstream os;
    os << "Type:        " << fp.version << "\n";
    os << "Cipher:      " << fp.cipher << "\n";
    if (fp.key_bits > 0)
        os << "Key size:    " << fp.key_bits << "-bit " << fp.key_exchange << "\n";
    else
        os << "Key exchange: " << fp.key_exchange << "\n";
    if (!fp.suggested_attack.empty())
        os << "\nSuggested:   " << fp.suggested_attack << "\n";

    m_fpOutput->setPlainText(QString::fromStdString(os.str()));

    for (const auto &flag : fp.risk_flags) {
        QListWidgetItem *item = new QListWidgetItem(QString::fromStdString(flag));
        bool critical = (flag.find("DROWN") != std::string::npos ||
                        flag.find("WEAK") != std::string::npos ||
                        flag.find("exposed") != std::string::npos);
        bool warning = (flag.find("POODLE") != std::string::npos ||
                       flag.find("BEAST") != std::string::npos ||
                       flag.find("ROBOT") != std::string::npos ||
                       flag.find("CBC") != std::string::npos);
        if (critical)
            item->setForeground(QColor(255, 60, 60));
        else if (warning)
            item->setForeground(QColor(255, 170, 0));
        else
            item->setForeground(QColor(0, 200, 100));
        m_fpIssues->addItem(item);
    }
}

void TlsAttackDialog::onDecrypt() {
    m_sdOutput->setPlainText(
        "TLS session decryption requires pcap integration (planned)\n\n"
        "This feature will be implemented in a future iteration with libpcap.\n"
        "The following parameters were captured:\n"
        "  TLS Version: " + m_sdVersion->currentText() + "\n" +
        "  Cipher Suite: " + m_sdCipher->currentText() + "\n\n"
        "For now, export the TLS handshake and use the Certificate Parser tab\n"
        "to analyse the server certificate, then run RSA attacks from there."
    );
}

void TlsAttackDialog::onParseCert() {
    m_certTree->clear();
    std::string input = m_certInput->toPlainText().toStdString();
    if (input.empty()) return;

    CertInfo ci = parse_certificate(input);

    auto addItem = [&](const QString &field, const QString &value, const QColor &color = QColor(224, 224, 240)) {
        QTreeWidgetItem *item = new QTreeWidgetItem({field, value});
        item->setForeground(0, QColor(136, 128, 160));
        item->setForeground(1, color);
        m_certTree->addTopLevelItem(item);
    };

    addItem("Subject CN", QString::fromStdString(ci.subject_cn));
    addItem("Subject O", QString::fromStdString(ci.subject_o));
    addItem("Issuer", QString::fromStdString(ci.issuer));
    addItem("Valid From", QString::fromStdString(ci.valid_from));
    addItem("Valid Until", QString::fromStdString(ci.valid_until));
    addItem("Public Key Algorithm", QString::fromStdString(ci.pubkey_algo));
    if (ci.pubkey_bits > 0)
        addItem("Public Key Bits", QString::number(ci.pubkey_bits));
    addItem("Serial Number (hex)", QString::fromStdString(ci.serial_hex));
    addItem("SHA256 Fingerprint", QString::fromStdString(ci.sha256_fingerprint));

    if (ci.pubkey_algo == "RSA") {
        addItem("Modulus (hex)", QString::fromStdString(ci.modulus_hex), QColor(0, 204, 136));
        addItem("Exponent (hex)", QString::fromStdString(ci.exponent_hex), QColor(0, 204, 136));
    }

    std::string san_str;
    for (size_t i = 0; i < ci.san_entries.size(); i++) {
        if (!san_str.empty()) san_str += "\n";
        san_str += ci.san_entries[i];
    }
    if (!san_str.empty())
        addItem("Subject Alt Names", QString::fromStdString(san_str));

    std::string ku_str;
    for (size_t i = 0; i < ci.key_usage.size(); i++) {
        if (!ku_str.empty()) ku_str += ", ";
        ku_str += ci.key_usage[i];
    }
    if (!ku_str.empty())
        addItem("Key Usage", QString::fromStdString(ku_str));

    addItem("Self-Signed", ci.is_self_signed ? "Yes" : "No",
            ci.is_self_signed ? QColor(255, 170, 0) : QColor(0, 200, 100));
}

void TlsAttackDialog::onExtractRsa() {
    // Find modulus and exponent from the tree
    QString mod, exp;
    for (int i = 0; i < m_certTree->topLevelItemCount(); i++) {
        QTreeWidgetItem *item = m_certTree->topLevelItem(i);
        if (item->text(0) == "Modulus (hex)")
            mod = item->text(1);
        if (item->text(0) == "Exponent (hex)")
            exp = item->text(1);
    }
    if (mod.isEmpty()) {
        // Try parsing again from input
        onParseCert();
        for (int i = 0; i < m_certTree->topLevelItemCount(); i++) {
            QTreeWidgetItem *item = m_certTree->topLevelItem(i);
            if (item->text(0) == "Modulus (hex)")
                mod = item->text(1);
            if (item->text(0) == "Exponent (hex)")
                exp = item->text(1);
        }
    }
    if (!mod.isEmpty())
        emit rsaParamsExtracted(mod, exp);
}

void TlsAttackDialog::onCheckExpiry() {
    QString validUntil;
    for (int i = 0; i < m_certTree->topLevelItemCount(); i++) {
        QTreeWidgetItem *item = m_certTree->topLevelItem(i);
        if (item->text(0) == "Valid Until")
            validUntil = item->text(1);
    }
    if (validUntil.isEmpty()) {
        m_certCheckExpiry->setText("No date parsed");
        return;
    }

    // Parse "YYYY-MM-DD HH:MM:SS UTC" format
    QDateTime dt = QDateTime::fromString(validUntil.left(19), "yyyy-MM-dd HH:mm:ss");
    if (!dt.isValid()) {
        m_certCheckExpiry->setText("Cannot parse date");
        return;
    }
    dt.setTimeZone(QTimeZone::UTC);

    if (dt < QDateTime::currentDateTimeUtc()) {
        m_certCheckExpiry->setStyleSheet("background:#cc2222; color:#fff; font-weight:bold;");
        m_certCheckExpiry->setText("EXPIRED");
    } else {
        m_certCheckExpiry->setStyleSheet("background:#00aa77; color:#fff; font-weight:bold;");
        m_certCheckExpiry->setText("Valid (expires " + dt.toString("yyyy-MM-dd") + ")");
    }
}
