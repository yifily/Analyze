#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "hexlib/qhexedit.h"
#include <QTreeWidget>
#include <QHBoxLayout>
#include <QSpacerItem>
#include <QSplitter>
#include <QDropEvent>
#include <QMimeData>
#include <QLabel>
#include <QFileDialog>
#include <QMessageBox>
#include <QFontDialog>
#include "elf/elf_analyze.h"
#include <QDebug>

class MyQTreeWidgetItem:public QTreeWidgetItem
{

public:
    MyQTreeWidgetItem(QTreeWidget *param=0)
        :QTreeWidgetItem(param)
    {
    }
    MyQTreeWidgetItem(QTreeWidget *param,const QStringList &strings)
        :QTreeWidgetItem(param,strings)
    {
    }
    MyQTreeWidgetItem(QTreeWidgetItem *param,const QStringList &strings)
        :QTreeWidgetItem(param,strings)
    {
    }

public:
    addr_node addinfo;

};


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{

    setAcceptDrops(true);
    ui->setupUi(this);
    InitGui();
    initStatus();
    initMenubar();
    LoadGlobalStyle();


    connect(this,&MainWindow::Loadfile_Scuess,this,&MainWindow::OnLoadFile);
    //LoadFile(".//libnative-lib.so");
    //LoadFile(".//main.elf");
    // 选择区域
    m_hexedit->setAddressWidth(8);

}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::InitGui()
{
    this->setGeometry(200,200,1400,800);
    ;
    // 加入左边数据hexedit，右边列表treewidget
    this->m_hexedit = new QHexEdit(this);
    this->m_datatree = new QTreeWidget(this);
    this->m_hexedit->setGeometry(0,0,780,100);
    this->m_hexedit->setObjectName("HexEdit");
    this->m_hexedit->setAddressAreaColor(QColor(245,222,179));
    connect(this->m_datatree,&QTreeWidget::itemClicked,this,&MainWindow::OnTreeItemClicked);


    // 添加分裂器，控件允许改变大小
    QSplitter * pSplitter = new QSplitter(Qt::Horizontal, ui->centralWidget);
    pSplitter->setOpaqueResize(true);
    pSplitter->setChildrenCollapsible(false);
    pSplitter->setLineWidth(10);
    // 加入hex编辑，树显示
    pSplitter->addWidget(m_hexedit);
    pSplitter->addWidget(m_datatree);
    // 填充布局中，填满整个屏幕
    ui->hlayout->addWidget(pSplitter);
    // 设置分割比例
    pSplitter->setStretchFactor(0,0);
    pSplitter->setStretchFactor(1,4);

    // 初始化Treewidget
    m_datatree->setColumnCount(3);  //设置列
    QStringList list;
    list.append(tr("field_name"));
    list.append(tr("field_value"));
    list.append(tr("comment"));
    m_datatree->setHeaderLabels(list);    //设置标题
    m_datatree->setColumnWidth(0,200);
    m_datatree->setColumnWidth(1,200);
}

void MainWindow::initStatus()
{
    // 添加状态栏
    m_lbAddressName = new QLabel();
    m_lbAddressName->setText(tr("Address:"));
    statusBar()->addPermanentWidget(m_lbAddressName);
    // 当前地址
    m_lbAddress = new QLabel();
    m_lbAddress->setFrameShape(QFrame::Panel);
    m_lbAddress->setFrameShadow(QFrame::Sunken);
    m_lbAddress->setMinimumWidth(70);
    statusBar()->addPermanentWidget(m_lbAddress);
    connect(this->m_hexedit,&QHexEdit::currentAddressChanged,
            [=](qint64 addr){
        this->m_lbAddress->setText(QString("0x%1").arg(addr, 1, 16));
    });


}

void MainWindow::initMenubar()
{
    // 添加菜单
    m_FileMenu = new QMenu(tr("File"));
    m_OpenAction = new QAction(tr("&Open"));
    m_OpenAction->setShortcut(Qt::CTRL | Qt::Key_O);

    m_SaveAction = new QAction(tr("Save"));
    m_SaveAction->setShortcut(Qt::CTRL | Qt::Key_S);

    m_FontAction = new QAction(tr("Font"));
    m_FontAction->setShortcut(Qt::CTRL | Qt::Key_A);

    m_FileMenu->addAction(m_OpenAction);
    m_FileMenu->addAction(m_SaveAction);
    m_FileMenu->addAction(m_FontAction);
    menuBar()->addMenu(m_FileMenu);

    // 添加点击事件
    // 打开文件
    connect(m_OpenAction,&QAction::triggered,
            [=](){
        // 要打开的文件
        QString fileNames = QFileDialog::getOpenFileName(this,tr("open"));
        if(!fileNames.isEmpty())
            this->LoadFile(fileNames);
    });
    // 保存文件
    connect(m_SaveAction,&QAction::triggered,
            [=](){
        // 要保存的文件
        QString fileNames = QFileDialog::getSaveFileName(this,tr("Save"));
        if(!fileNames.isEmpty())
            this->SaveFile(fileNames);
    });
    // 设置字体
    connect(m_FontAction,&QAction::triggered,
            [=](){
        // 选择字体
        bool ok;
        QFont font = QFontDialog::getFont(&ok,this);
        if(ok)
            this->SetGlobalFont(font);
    });



}

void MainWindow::SetGlobalFont(QFont &font)
{
    this->m_hexedit->setFont(font);
    this->m_datatree->setFont(font);
    this->m_FileMenu->setFont(font);
}

void MainWindow::SetCurrentFile(const QString &fileName)
{
    QString curpath = QFileInfo(fileName).canonicalFilePath();
    setWindowModified(false);
    if(m_file.exists())
    {
        setWindowFilePath(curpath + " - Analyze");
    }else {
        setWindowFilePath("Analyze");
    }
}

void MainWindow::LoadGlobalStyle()
{
    // 打开文件，如果文件存在的话
    QString displayString;
    QFile file;
    file.setFileName("./stylesheet.qss");
    if( !file.exists())
    {
        statusBar()->showMessage("stylesheet.qss not exists",10000);
        return ;
    }
    file.open(QIODevice::ReadOnly | QIODevice::Text);

    while(!file.atEnd())
    {
        QByteArray line = file.readLine();
        QString str(line);
        displayString.append(str);
    }
    file.close();
    this->setStyleSheet(displayString);
}

void MainWindow::LoadFile(const QString &file_name)
{
    QFileInfo info(file_name);
    m_file.setFileName(file_name);
    if(m_file.exists())
    {
        m_hexedit->setData(m_file);
        emit Loadfile_Scuess(m_hexedit->data().data());
    }
    SetCurrentFile(file_name);
    statusBar()->showMessage(tr("file load"),2000);
}

bool MainWindow::SaveFile(const QString &file_name)
{
    // 在临时文件中保存
    QString tmpFileName = file_name + ".~tmp";
    // 光标进入暂停状态
    QApplication::setOverrideCursor(Qt::WaitCursor);
    QFile file(tmpFileName);
    // 写入到临时文件中
    bool ok = this->m_hexedit->write(file);
    // 文件存在就先删除
    if (QFile::exists(file_name))
        ok = QFile::remove(file_name);
    // 拷贝文件
    if (ok)
    {
        file.setFileName(tmpFileName);
        ok = file.copy(file_name);
        if(ok)
            QFile::remove(tmpFileName);

    }
    // 写入完成后恢复光标状态
    QApplication::restoreOverrideCursor();
    statusBar()->showMessage(tr("file saved"),2000);
    return ok;
}

void MainWindow::ShowFileFomatELF(char *data)
{
    // 解析elf文件
    elf.SetElfData((uint8_t*)data);

    if(!elf.IsElfFile())
    {
        qDebug()<<"not elf file\n";
        return ;
    }

    // 2 加入头部信息
    MyQTreeWidgetItem *headitem = new MyQTreeWidgetItem(m_datatree,QStringList(QString("header")));
    headitem->addinfo.start_addr = 0;
    headitem->addinfo.len = sizeof(elf32_hdr);
    headitem->addinfo.value = 0;
    headitem->addinfo.info = "ELF_Head";

    // 2.1 e_ident信息
    MyQTreeWidgetItem *Head_ident = new MyQTreeWidgetItem(headitem,QStringList(QString("e_ident")));
    Head_ident->addinfo.start_addr = 0;
    Head_ident->addinfo.len = offsetof(Elf32_Ehdr,e_type);
    Head_ident->addinfo.value = 0;
    Head_ident->addinfo.info = "e_ident";

    // 2.1.1 EI_MAGIC
    MyQTreeWidgetItem *info1 = new  MyQTreeWidgetItem(Head_ident,QStringList(QString("EI_MAGIC")));
    info1->addinfo = elf.GetHeadField("e_ident",EI_MAG0);
    info1->setText(1,info1->addinfo.info);
    info1->setText(2,tr("elf magic"));


    // 2.1.2 EI_CLASS
    MyQTreeWidgetItem *info2 = new  MyQTreeWidgetItem(Head_ident,QStringList(QString("EI_CLASS")));
    info2->addinfo = elf.GetHeadField("e_ident",EI_CLASS);
    info2->setText(1,info2->addinfo.info);
    info2->setText(2,tr("elf class 32 or 64"));



    // 2.1.3 EI_DATA
    MyQTreeWidgetItem *info3 = new  MyQTreeWidgetItem(Head_ident,QStringList(QString("EI_DATA")));
    info3->addinfo = elf.GetHeadField("e_ident",EI_DATA);
    info3->setText(1,info3->addinfo.info);
    info3->setText(2,tr("elf data lsb or msb"));


    // 2.1.4 EI_VERSION
    MyQTreeWidgetItem *info4 = new  MyQTreeWidgetItem(Head_ident,QStringList(QString("EI_VERSION")));
    info4->addinfo = elf.GetHeadField("e_ident",EI_VERSION);
    info4->setText(1, info4->addinfo.info);
    info4->setText(2,tr("elf version need EV_CURRENT"));


    // 2.1.5 EI_PAD
    MyQTreeWidgetItem *info5 = new  MyQTreeWidgetItem(Head_ident,QStringList(QString("EI_PAD")));
    info5->addinfo =elf.GetHeadField("e_ident",EI_PAD);
    info5->setText(1,info5->addinfo.info);
    info5->setText(2,tr("pad null"));


    // 2.2 头部-文件类型 e_type
    MyQTreeWidgetItem *typeinfo = new  MyQTreeWidgetItem(headitem,QStringList(QString("e_type")));
    typeinfo->addinfo = elf.GetHeadField("e_type");
    typeinfo->setText(1,typeinfo->addinfo.info);
    typeinfo->setText(2,tr("elf type"));

    // 2.3 头部-文件类型 e_machine
    MyQTreeWidgetItem *machine = new  MyQTreeWidgetItem(headitem,QStringList(QString("e_machine")));
    machine->addinfo = elf.GetHeadField("e_machine");
    machine->setText(1,machine->addinfo.info);
    machine->setText(2,tr("elf machine"));


    // 2.4 头部-文件版本 e_version
    MyQTreeWidgetItem *version = new  MyQTreeWidgetItem(headitem,QStringList(QString("e_version")));
    version->addinfo = elf.GetHeadField("e_version");
    version->setText(1,version->addinfo.info);
    version->setText(2,tr("elf version"));

    // 2.5 头部-文件入口 e_entry
    MyQTreeWidgetItem *entry = new  MyQTreeWidgetItem(headitem,QStringList(QString("e_entry")));
    entry->addinfo = elf.GetHeadField("e_entry");
    entry->setText(1,entry->addinfo.info);
    entry->setText(2,tr("elf entry address"));

    // 2.6 头部-程序头入口 e_phoff
    MyQTreeWidgetItem *e_phoff = new  MyQTreeWidgetItem(headitem,QStringList(QString("e_phoff")));
    e_phoff->addinfo = elf.GetHeadField("e_phoff");
    e_phoff->setText(1,  e_phoff->addinfo.info);
    e_phoff->setText(2,tr("Program Header Table offset"));


    // 2.7 头部-区段头入口 e_shoff
    MyQTreeWidgetItem *e_shoff = new  MyQTreeWidgetItem(headitem,QStringList(QString("e_shoff")));
    e_shoff-> addinfo = elf.GetHeadField("e_shoff");
    e_shoff->setText(1,e_shoff->addinfo.info);
    e_shoff->setText(2,tr("Section Header Table offset"));



    // 2.8 头部-文件类型 e_flags
    MyQTreeWidgetItem *e_flags = new  MyQTreeWidgetItem(headitem,QStringList(QString("e_flags")));
    e_flags->addinfo = elf.GetHeadField("e_flags");
    e_flags->setText(1, e_flags->addinfo.info);


    // 2.9 头部-头部大小 e_ehsize
    MyQTreeWidgetItem *ehsize  = new  MyQTreeWidgetItem(headitem,QStringList(QString("e_ehsize")));
    ehsize ->addinfo = elf.GetHeadField("e_ehsize");
    ehsize ->setText(1,ehsize ->addinfo.info);
    ehsize ->setText(2,tr("elf Header size"));


    // 2.10 头部-程序头表项大小 e_phentsize
    MyQTreeWidgetItem *e_phentsize  = new  MyQTreeWidgetItem(headitem,QStringList(QString("e_phentsize")));

    e_phentsize-> addinfo = elf.GetHeadField("e_phentsize");
    e_phentsize->setText(1,e_phentsize->addinfo.info);
    e_phentsize->setText(2,tr("Program Table size"));


    // 2.11 头部-程序头表项个数 e_phnum
    MyQTreeWidgetItem *phnum   = new  MyQTreeWidgetItem(headitem,QStringList(QString("e_phnum")));
    phnum ->addinfo = elf.GetHeadField("e_phnum");
    phnum ->setText(1, phnum ->addinfo.info);
    phnum ->setText(2,tr("Program count"));


    // 2.12 头部-区段头表项大小 e_shentsize
    MyQTreeWidgetItem *e_shentsize  = new  MyQTreeWidgetItem(headitem,QStringList(QString("e_shentsize")));
    e_shentsize->addinfo = elf.GetHeadField("e_shentsize");
    e_shentsize->setText(1,e_shentsize->addinfo.info);
    e_shentsize->setText(2,tr("Section Table size"));


    // 2.13 头部-区段头表项个数 e_shnum
    MyQTreeWidgetItem *e_shnum  = new  MyQTreeWidgetItem(headitem,QStringList(QString("e_shnum")));
    e_shnum->addinfo = elf.GetHeadField("e_shnum");
    e_shnum->setText(1,e_shnum->addinfo.info);
    e_shnum->setText(2,tr("Section count "));


    // 2.14 头部-字符区段下标 e_shstrndx
    MyQTreeWidgetItem *e_shstrndx  = new  MyQTreeWidgetItem(headitem,QStringList(QString("e_shstrndx")));
    e_shstrndx->addinfo = elf.GetHeadField("e_shstrndx");
    e_shstrndx->setText(1,e_shstrndx->addinfo.info);
    e_shstrndx->setText(2,tr("string Section index "));

    // 目前不支持elf64
    if(elf.IsElf64())
        return;

    // 3. 程序段信息
    MyQTreeWidgetItem *program  = new  MyQTreeWidgetItem(m_datatree,QStringList(QString(tr("program"))));
    program->addinfo = elf.GetProgramInfo(0,"program_head");
    int count = elf.GetProgramCount();
    for (int i = 0; i < count; ++i) {
        ShowProgramInfo(program,i);
    }



    // 3. 区序段信息
    MyQTreeWidgetItem *section  = new  MyQTreeWidgetItem(m_datatree,QStringList(QString(tr("section"))));
    section->addinfo = elf.GetSectionInfo(0,"section_head");
    count = elf.GetSectionCount();
    for (int i = 0; i < count; ++i) {
        ShowSectionInfo(section,i);
    }

    // 4.解析符号表(导出表)
    count = elf.GetSymbolCount();
    if(count >0)
    {
        MyQTreeWidgetItem *symbol  = new  MyQTreeWidgetItem(m_datatree,QStringList(QString(tr("symbol"))));
        symbol->addinfo = elf.GetSymbolInfo(0,"all_head");
        for (int i = 0; i < count; ++i) {
            ShowSymbolInfo(symbol,i);
        }
    }

    // 5.解析动态符号表(导入表) SHT_DYNAMIC
    count =elf.GetDynamicSymbolCount();
    if( count>0)
    {
        MyQTreeWidgetItem *dynamic  = new  MyQTreeWidgetItem(m_datatree,QStringList(QString(tr("dynamicsymbol"))));
        dynamic->addinfo = elf.GetDynamicSymbolInfo(0,"all_head");
        for (int i = 0; i < count; ++i) {
            ShowDynamicSymbolInfo(dynamic,i);
        }
    }



    m_datatree->insertTopLevelItem(0,headitem);
    m_datatree->setItemsExpandable(true);
}

void MainWindow::ShowProgramInfo(QTreeWidgetItem *param, int index)
{
    QString showname = QString("program_talbe[%1]").arg(index);
    MyQTreeWidgetItem *program_name_item  = new  MyQTreeWidgetItem(param,QStringList(showname));
    program_name_item->addinfo = elf.GetProgramInfo(index,"p_head");


    QString Names[8] = {"p_type","p_offset","p_vaddr","p_paddr","p_filesz","p_memsz","p_flags","p_align"};

    for(int i =0;i<8;i++)
    {

        MyQTreeWidgetItem *info  = new  MyQTreeWidgetItem(program_name_item,QStringList(Names[i]));
        info->addinfo =  elf.GetProgramInfo(index,Names[i]);
        info->setText(1,info->addinfo.info);
        info->setText(2,tr("program %1").arg(Names[i]));
    }

}

void MainWindow::ShowSectionInfo(QTreeWidgetItem *param, int index)
{
    QString showname = QString("section_talbe[%1]").arg(index);
    MyQTreeWidgetItem *section_name_item  = new  MyQTreeWidgetItem(param,QStringList(showname));
    section_name_item->addinfo = elf.GetSectionInfo(index,"head");
    section_name_item->setText(1,section_name_item->addinfo.info);

    QString Names[10] = {"sh_name","sh_type","sh_flags","sh_addr",
                         "sh_offset","sh_size","sh_link","sh_info","sh_addralign","sh_entsize"};
    for(int i =0;i<10;i++)
    {

        MyQTreeWidgetItem *info  = new  MyQTreeWidgetItem(section_name_item,QStringList(Names[i]));
        info->addinfo =  elf.GetSectionInfo(index,Names[i]);
        info->setText(1,info->addinfo.info);
        info->setText(2,tr("section %1").arg(Names[i]));
    }

}

void MainWindow::ShowSymbolInfo(QTreeWidgetItem *param, int index)
{
    QString showname = QString("symbol_talbe[%1]").arg(index);
    MyQTreeWidgetItem *symbol_name_item  = new  MyQTreeWidgetItem(param,QStringList(showname));
    symbol_name_item->addinfo = elf.GetSymbolInfo(index,"head");
    symbol_name_item->setText(1,symbol_name_item->addinfo.info);

    QString Names[6] = {"st_name","st_value","st_size","st_info",
                         "st_other","st_shndx"
                         };
    for(int i =0;i<6;i++)
    {

        MyQTreeWidgetItem *info  = new  MyQTreeWidgetItem(symbol_name_item,QStringList(Names[i]));
        info->addinfo =  elf.GetSymbolInfo(index,Names[i]);
        info->setText(1,info->addinfo.info);
        info->setText(2,tr("section %1").arg(Names[i]));
    }


}

void MainWindow::ShowDynamicSymbolInfo(QTreeWidgetItem *param, int index)
{
    QString showname = QString("Dynamic_talbe[%1]").arg(index);
    MyQTreeWidgetItem *Dynamic_name_item  = new  MyQTreeWidgetItem(param,QStringList(showname));
    Dynamic_name_item->addinfo = elf.GetDynamicSymbolInfo(index,"head");
    Dynamic_name_item->setText(1,Dynamic_name_item->addinfo.info);

    QString Names[6] = {"st_name","st_value","st_size","st_info",
                         "st_other","st_shndx"
                         };
    for(int i =0;i<6;i++)
    {

        MyQTreeWidgetItem *info  = new  MyQTreeWidgetItem(Dynamic_name_item,QStringList(Names[i]));
        info->addinfo =  elf.GetDynamicSymbolInfo(index,Names[i]);
        info->setText(1,info->addinfo.info);
        info->setText(2,tr("section %1").arg(Names[i]));
    }






}

void MainWindow::OnLoadFile(char *data)
{
    m_datatree->clear();
    ShowFileFomatELF(data);

}

void MainWindow::OnTreeItemClicked(QTreeWidgetItem *item, int)
{
    addr_node user = ((MyQTreeWidgetItem*)item)->addinfo;
    // 选择区域

    m_hexedit->setSelection(user.start_addr,user.len);
    qDebug()<<user.start_addr << " "<<user.len;


}

void MainWindow::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls())
        event->accept();
}

void  MainWindow::dropEvent(QDropEvent *event)
{

    if (event->mimeData()->hasUrls())
    {
        QList<QUrl> urls = event->mimeData()->urls();
        QString filePaht = urls.at(0).toLocalFile();
        this->LoadFile(filePaht);
        event->accept();
    }

}
