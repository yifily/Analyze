#ifndef ELF_ANALYZE_H
#define ELF_ANALYZE_H
#include"elf.h"
#include <QString>
#include <qobject.h>

struct addr_node
{
    int64_t start_addr;  //所在地址
    int32_t len;         //数据长度
    int32_t value;       //数据
    QString info;        //用于显示信息
    QString field;       //字段信息
};




class AnalyzeElf
{
public:
    AnalyzeElf()=default;
    AnalyzeElf(uint8_t *buff);
    void SetElfData(uint8_t * buff);
    bool IsElfFile();
    bool IsElf64();

    Elf32_Ehdr * AnalyzeHeader32(uint8_t *buff =nullptr);
    Elf64_Ehdr * AnalyzeHeader64(uint8_t *buff =nullptr);
    addr_node GetHeadField(const QString &field_name,uint8_t id =-1, uint8_t *buff = nullptr);

    addr_node GetHeadField64(const QString &field_name,uint8_t id =-1, uint8_t *buff = nullptr);
    addr_node GetHeadField32(const QString &field_name,uint8_t id =-1, uint8_t *buff = nullptr);

    Elf32_Shdr *GetSection();
    Elf32_Shdr *GetSectionIndex(int index);

    // 给定一个区段，解析成符号表地址
    char * GetSectionParseSymbolTableOffset(int index,int offset);

    Elf32_Shdr *GetSymbolSection();
    Elf32_Shdr *GetDynamicSymbolSection();

    // 获取程序段个数
    int GetProgramCount();
    int GetSectionCount();
    int GetDynamicSymbolCount();
    int GetSymbolCount();


    // 获取第n个程序表信息
    addr_node GetProgramInfo(int i,const QString &field_name);
    addr_node GetSectionInfo(int i,const QString &field_name);

    enum symbole_type{symbol = 0,dymamicsymbol};
    addr_node GetSymbolInfo(int i,const QString &field_name);
    addr_node GetDynamicSymbolInfo(int i,const QString &field_name);
    addr_node GetSelectSymbolInfo(int i,const QString &field_name,symbole_type);

    // 从区段符号表中获取符号
    QString  GetStringTableIndex(int offset);
    // 获取区段符号表 tables
    char * GetStringTableOffset();


private:
    bool m_isElf64;
    uint8_t *m_buff;
    Elf32_Ehdr *m_Ehdr32;
    Elf64_Ehdr *m_Ehdr64;
};



#endif
