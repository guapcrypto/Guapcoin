// Copyright (c) 2019 The PIVX developers
// Copyright (c) 2019-2020 The Guapcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef COINCONTROLGUAPWIDGET_H
#define COINCONTROLGUAPWIDGET_H

#include <QDialog>

namespace Ui {
class CoinControlGuapWidget;
}

class CoinControlGuapWidget : public QDialog
{
    Q_OBJECT

public:
    explicit CoinControlGuapWidget(QWidget *parent = nullptr);
    ~CoinControlGuapWidget();

private:
    Ui::CoinControlGuapWidget *ui;
};

#endif // COINCONTROLGUAPWIDGET_H
