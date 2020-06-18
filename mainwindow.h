#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFile>

#include <elf/elf_analyze.h>
class QHexEdit;
class QTreeWidget;
class QLabel;
class QTreeWidgetItem;


namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    // 初始化窗口
    void InitGui();
    void initStatus();
    void initMenubar();


    // 设置全局字体
    void SetGlobalFont(QFont & font);
    void SetCurrentFile(const QString&fileName);
    void LoadGlobalStyle();


private:
    Ui::MainWindow *ui;
    QHexEdit *m_hexedit;
    QTreeWidget *m_datatree;
    QLabel *m_lbAddressName;
    QLabel *m_lbAddress;

    QMenu * m_FileMenu;
    QAction *m_OpenAction;
    QAction *m_SaveAction;
    QAction *m_FontAction;
    AnalyzeElf elf;

    // 加载的文件
    QFile m_file;
    void LoadFile(const QString &file_name);
    bool SaveFile(const QString &file_name);

    // 显示文件界面
    void ShowFileFomatELF( char *data);
    void ShowProgramInfo(QTreeWidgetItem *param,int i);
    void ShowSectionInfo(QTreeWidgetItem *param,int i);
    void ShowSymbolInfo(QTreeWidgetItem *param,int i);
    void ShowDynamicSymbolInfo(QTreeWidgetItem *param,int i);



 signals:
    void Loadfile_Scuess(char * data);

public slots:
    void OnLoadFile(char *data);
    void OnTreeItemClicked(QTreeWidgetItem *item,int i);



protected:
    // 文件拖拽消息
    void dragEnterEvent(QDragEnterEvent *event);
    // 文件放下
    void dropEvent(QDropEvent *event);
};

#endif // MAINWINDOW_H
