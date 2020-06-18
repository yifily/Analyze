#include"elf_analyze.h"
#include <string.h>
#include <QDebug>



AnalyzeElf::AnalyzeElf(uint8_t *buff)
{
    m_buff = buff;
    m_isElf64 = IsElf64();
}

void AnalyzeElf::SetElfData(uint8_t *buff)
{
    m_buff = buff;
    m_isElf64 = IsElf64();
}

bool AnalyzeElf::IsElfFile()
{
    if(0==memcmp((char*)m_buff,ELFMAG,4))
    {
        return true;
    }
    return false;
}

bool AnalyzeElf::IsElf64()
{
    if(m_buff[EI_CLASS]==ELFCLASS64)
    {
        return true;
    }
    return  false;
}

Elf32_Ehdr *AnalyzeElf::AnalyzeHeader32(uint8_t *buff)
{
    if(buff != nullptr)
        return (Elf32_Ehdr*)buff;
    else
        return (Elf32_Ehdr*)m_buff;
}

Elf64_Ehdr *AnalyzeElf::AnalyzeHeader64(uint8_t *buff)
{
    if(buff != nullptr)
        return (Elf64_Ehdr*)buff;
    else
        return (Elf64_Ehdr*)m_buff;
}


addr_node AnalyzeElf::GetHeadField(const QString &field_name, uint8_t id, uint8_t *buff)
{
    return m_isElf64?GetHeadField64(field_name,id,buff):GetHeadField32(field_name,id,buff);
}

addr_node AnalyzeElf::GetHeadField64(const QString &field_name, uint8_t id, uint8_t *buff)
{
    Elf64_Ehdr *pEhdr;
    pEhdr = AnalyzeHeader64(buff);
    addr_node node={};
    node.field = field_name;
    if(field_name == "e_ident")
    {
        // 解析标志
        switch (id) {
        case EI_MAG0:
        case EI_MAG1:
        case EI_MAG2:
        case EI_MAG3:
            node.start_addr = 0;
            node.len = 4;
            node.value = 0;
            node.info = ELFMAG;

            return node;
            break;
            // 解析类型
        case EI_CLASS:
        {
            const QString ei_class[] = {"ELFCLASSNONE","ELFCLASS32","ELFCLASS64"};
            int value = (pEhdr)->e_ident[EI_CLASS];
            node.info = QString("%1 (%2)").arg(value).arg(ei_class[value]);
            node.len = 1;
            node.start_addr = EI_CLASS;
            node.value = value;
            return node;

        }break;
            // 解析编码方式
        case EI_DATA:
        {
            const QString ei_data[] = {"ELFDATANONE","ELFDATA2LSB","ELFDATA2MSB"};
            int value = pEhdr->e_ident[EI_DATA];
            node.info = QString("%1 (%2)").arg(value).arg(ei_data[value]);
            node.len = 1;
            node.start_addr = EI_DATA;
            node.value = value;
            return node;

        }break;
            // 解析文件版本
        case EI_VERSION:
        {
            int value = pEhdr->e_ident[EI_VERSION];
            node.info =  QString("%1 (%2)").arg(value).arg("EV_CURRENT");
            node.len = 1;
            node.start_addr = EI_VERSION;
            node.value = value;
            return node;

        }break;
            // 解析其他
        case EI_PAD:
        {
            int value = pEhdr->e_ident[EI_PAD];
            node.info = QString("%1").arg(value);
            node.len = 9;
            node.start_addr = EI_PAD;
            node.value = value;
            return node;
        }break;

        }
    }
    else if(field_name == "e_type")
    {
        const QString types[] = {"ET_NONEET_NONE","ET_REL","ET_EXEC","ET_DYN","ET_CORE","ET_LOPROC","ET_HIPROC","ET_LOPROC"};
        int value = pEhdr->e_type;
        if(value <5 )
            node.info =   QString("%1 (%2)").arg(value).arg(types[value]);
        else if(value > ET_LOPROC )
            node.info =   QString("%1 ").arg(value);
        node.len = sizeof (pEhdr->e_type);
        node.start_addr = offsetof(Elf64_Ehdr,e_type);
        node.value = value;
        return node;
    }
    else if(field_name == "e_machine")
    {
        const QString types[] = {"EM_NONE","EM_M32","EM_SPARC","EM_386","EM_68K","EM_88K","EM_860","EM_MIPS"};
        int value = pEhdr->e_machine;
        if(value<9)
            node.info =  QString("%1 (%2)").arg(value).arg(types[value]);
        else if(value == EM_X86_64)
            node.info =  QString("%1 (%2)").arg(value).arg("EM_X86_64");
        else
            node.info =  QString("%1 (%2)").arg(value).arg("other");

        node.len = sizeof (pEhdr->e_machine);
        node.start_addr = offsetof(Elf64_Ehdr,e_machine);
        node.value = value;
        return node;
    }
    else if(field_name == "e_version")
    {

        const QString version[] = {"EV_NONE","EV_CURRENT"};
        int value = pEhdr->e_version;
        node.info =  QString("%1 (%2)").arg(value).arg(version[value]);
        node.len =  sizeof (pEhdr->e_version);
        node.start_addr = offsetof(Elf64_Ehdr,e_version);
        node.value = value;
        return node;
    }
    else if(field_name == "e_entry")
    {
        int value = pEhdr->e_entry;
        node.info =  QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.len = sizeof (pEhdr->e_entry);
        node.start_addr = offsetof(Elf64_Ehdr,e_entry);
        node.value = value;
        return node;
    }
    else if(field_name == "e_phoff")
    {
        int value = pEhdr->e_phoff;
        node.info = QString("%1").arg(value);
        node.len = sizeof (pEhdr->e_phoff);
        node.start_addr = offsetof(Elf64_Ehdr,e_phoff);
        node.value = value;
        return node;
    }
    else if(field_name == "e_shoff")
    {
        int value = pEhdr->e_shoff;
        node.info =  QString("%1").arg(value);
        node.len =sizeof (pEhdr->e_shoff);
        node.start_addr = offsetof(Elf64_Ehdr,e_shoff);
        node.value = value;
        return node;
    }
    else if(field_name == "e_flags")
    {
        int value = pEhdr->e_flags;
        node.info =  QString("%1").arg(value);
        node.len = sizeof (pEhdr->e_flags);
        node.start_addr = offsetof(Elf64_Ehdr,e_flags);
        node.value = value;
        return node;
    }
    else if(field_name == "e_ehsize")
    {
        int value = pEhdr->e_ehsize;
        node.info =  QString("%1").arg(value);
        node.len = sizeof(pEhdr->e_ehsize);
        node.start_addr = offsetof(Elf64_Ehdr,e_ehsize);
        node.value = value;
        return node;
    }

    else if(field_name == "e_phentsize")
    {
        int value = pEhdr->e_phentsize;
        node.info =  QString("%1").arg(value);
        node.len = sizeof(pEhdr->e_phentsize);
        node.start_addr = offsetof(Elf64_Ehdr,e_phentsize);
        node.value = value;
        return node;
    }
    else if(field_name == "e_phnum")
    {
        int value = pEhdr->e_phnum;
        node.info =  QString("%1").arg(value);
        node.len = sizeof(pEhdr->e_phnum);
        node.start_addr = offsetof(Elf64_Ehdr,e_phnum);
        node.value = value;
        return node;
    }
    else if(field_name == "e_shentsize")
    {
        int value = pEhdr->e_shentsize;
        node.info =  QString("%1").arg(value);
        node.len = sizeof(pEhdr->e_shentsize);
        node.start_addr = offsetof(Elf64_Ehdr,e_shentsize);
        node.value = value;
        return node;
    }
    else if(field_name == "e_shnum")
    {
        int value = pEhdr->e_shnum;
        node.info =  QString("%1").arg(value);
        node.len =sizeof(pEhdr->e_shnum);
        node.start_addr = offsetof(Elf64_Ehdr,e_shnum);
        node.value = value;
        return node;
    }
    else if(field_name == "e_shstrndx")
    {
        int value = pEhdr->e_shstrndx;
        node.info =  QString("%1").arg(value);
        node.len = sizeof(pEhdr->e_shstrndx);
        node.start_addr = offsetof(Elf64_Ehdr,e_shstrndx);
        node.value = value;
        return node;
    }


    return node;
}

addr_node AnalyzeElf::GetHeadField32(const QString &field_name, uint8_t id, uint8_t *buff)
{
    Elf32_Ehdr *pEhdr;
    pEhdr = AnalyzeHeader32(buff);


    addr_node node={};
    node.field = field_name;
    if(field_name == "e_ident")
    {
        // 解析标志
        switch (id) {
        case EI_MAG0:
        case EI_MAG1:
        case EI_MAG2:
        case EI_MAG3:
            node.start_addr = 0;
            node.len = 4;
            node.value = 0;
            node.info = ELFMAG;

            return node;
            break;
            // 解析类型
        case EI_CLASS:
        {
            const QString ei_class[] = {"ELFCLASSNONE","ELFCLASS32","ELFCLASS64"};
            int value = (pEhdr)->e_ident[EI_CLASS];
            node.info = QString("%1 (%2)").arg(value).arg(ei_class[value]);
            node.len = 1;
            node.start_addr = EI_CLASS;
            node.value = value;
            return node;

        }break;
            // 解析编码方式
        case EI_DATA:
        {
            const QString ei_data[] = {"ELFDATANONE","ELFDATA2LSB","ELFDATA2MSB"};
            int value = pEhdr->e_ident[EI_DATA];
            node.info = QString("%1 (%2)").arg(value).arg(ei_data[value]);
            node.len = 1;
            node.start_addr = EI_DATA;
            node.value = value;
            return node;

        }break;
            // 解析文件版本
        case EI_VERSION:
        {
            int value = pEhdr->e_ident[EI_VERSION];
            node.info =  QString("%1 (%2)").arg(value).arg("EV_CURRENT");
            node.len = 1;
            node.start_addr = EI_VERSION;
            node.value = value;
            return node;

        }break;
            // 解析其他
        case EI_PAD:
        {
            int value = pEhdr->e_ident[EI_PAD];
            node.info = QString("%1").arg(value);
            node.len = 9;
            node.start_addr = EI_PAD;
            node.value = value;
            return node;
        }break;

        }
    }
    else if(field_name == "e_type")
    {
        const QString types[] = {"ET_NONEET_NONE","ET_REL","ET_EXEC","ET_DYN","ET_CORE","ET_LOPROC","ET_HIPROC","ET_LOPROC"};
        int value = pEhdr->e_type;
        if(value <5 )
            node.info =   QString("%1 (%2)").arg(value).arg(types[value]);
        else if(value > ET_LOPROC )
            node.info =   QString("%1 ").arg(value);
        node.len = sizeof (pEhdr->e_type);
        node.start_addr = offsetof(Elf32_Ehdr,e_type);
        node.value = value;
        return node;
    }
    else if(field_name == "e_machine")
    {
        const QString types[] = {"EM_NONE","EM_M32","EM_SPARC","EM_386","EM_68K","EM_88K","EM_860","EM_MIPS"};
        int value = pEhdr->e_machine;
        if(value<9)
            node.info =  QString("%1 (%2)").arg(value).arg(types[value]);
        else if(value == EM_X86_64)
            node.info =  QString("%1 (%2)").arg(value).arg("EM_X86_64");
        else
            node.info =  QString("%1 (%2)").arg(value).arg("other");

        node.len = sizeof (pEhdr->e_machine);
        node.start_addr = offsetof(Elf32_Ehdr,e_machine);
        node.value = value;
        return node;
    }
    else if(field_name == "e_version")
    {

        const QString version[] = {"EV_NONE","EV_CURRENT"};
        int value = pEhdr->e_version;
        node.info =  QString("%1 (%2)").arg(value).arg(version[value]);
        node.len =  sizeof (pEhdr->e_version);
        node.start_addr = offsetof(Elf32_Ehdr,e_version);
        node.value = value;
        return node;
    }
    else if(field_name == "e_entry")
    {
        int value = pEhdr->e_entry;
        node.info =  QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.len = sizeof (pEhdr->e_entry);
        node.start_addr = offsetof(Elf32_Ehdr,e_entry);
        node.value = value;
        return node;
    }
    else if(field_name == "e_phoff")
    {
        int value = pEhdr->e_phoff;
        node.info = QString("%1").arg(value);
        node.len = sizeof (pEhdr->e_phoff);
        node.start_addr = offsetof(Elf32_Ehdr,e_phoff);
        node.value = value;
        return node;
    }
    else if(field_name == "e_shoff")
    {
        int value = pEhdr->e_shoff;
        node.info =  QString("%1").arg(value);
        node.len =sizeof (pEhdr->e_shoff);
        node.start_addr = offsetof(Elf32_Ehdr,e_shoff);
        node.value = value;
        return node;
    }
    else if(field_name == "e_flags")
    {
        int value = pEhdr->e_flags;
        node.info =  QString("%1").arg(value);
        node.len = sizeof (pEhdr->e_flags);
        node.start_addr = offsetof(Elf32_Ehdr,e_flags);
        node.value = value;
        return node;
    }
    else if(field_name == "e_ehsize")
    {
        int value = pEhdr->e_ehsize;
        node.info =  QString("%1").arg(value);
        node.len = sizeof(pEhdr->e_ehsize);
        node.start_addr = offsetof(Elf32_Ehdr,e_ehsize);
        node.value = value;
        return node;
    }

    else if(field_name == "e_phentsize")
    {
        int value = pEhdr->e_phentsize;
        node.info =  QString("%1").arg(value);
        node.len = sizeof(pEhdr->e_phentsize);
        node.start_addr = offsetof(Elf32_Ehdr,e_phentsize);
        node.value = value;
        return node;
    }
    else if(field_name == "e_phnum")
    {
        int value = pEhdr->e_phnum;
        node.info =  QString("%1").arg(value);
        node.len = sizeof(pEhdr->e_phnum);
        node.start_addr = offsetof(Elf32_Ehdr,e_phnum);
        node.value = value;
        return node;
    }
    else if(field_name == "e_shentsize")
    {
        int value = pEhdr->e_shentsize;
        node.info =  QString("%1").arg(value);
        node.len = sizeof(pEhdr->e_shentsize);
        node.start_addr = offsetof(Elf32_Ehdr,e_shentsize);
        node.value = value;
        return node;
    }
    else if(field_name == "e_shnum")
    {
        int value = pEhdr->e_shnum;
        node.info =  QString("%1").arg(value);
        node.len =sizeof(pEhdr->e_shnum);
        node.start_addr = offsetof(Elf32_Ehdr,e_shnum);
        node.value = value;
        return node;
    }
    else if(field_name == "e_shstrndx")
    {
        int value = pEhdr->e_shstrndx;
        node.info =  QString("%1").arg(value);
        node.len = sizeof(pEhdr->e_shstrndx);
        node.start_addr = offsetof(Elf32_Ehdr,e_shstrndx);
        node.value = value;
        return node;
    }


    return node;
}

Elf32_Shdr *AnalyzeElf::GetSection()
{
    Elf32_Ehdr *pEhdr =  AnalyzeHeader32();
    return (Elf32_Shdr*)(m_buff + pEhdr->e_shoff);
}

Elf32_Shdr *AnalyzeElf::GetSectionIndex(int index)
{
    Elf32_Ehdr *pEhdr =  AnalyzeHeader32();
    Elf32_Shdr* pshdr = (Elf32_Shdr*)(m_buff + pEhdr->e_shoff);
    return  &pshdr[index];
}

char *AnalyzeElf::GetSectionParseSymbolTableOffset(int index, int offset)
{
    // 获取区段表，当成字符串表解析
    Elf32_Shdr* pshdr =GetSectionIndex(index);
    char *pString = (char*)(pshdr->sh_offset + m_buff + offset);
    if(strlen(pString) == 0 )
        return (char*)"unkown";
    return pString;
}

Elf32_Shdr *AnalyzeElf::GetSymbolSection()
{
    Elf32_Shdr*pShdr =  GetSection();
    for (int i =0;i<GetSectionCount();i++) {
        if(pShdr[i].sh_type == SHT_SYMTAB)
        {
            return &pShdr[i];
        }
    }
    return nullptr;
}

Elf32_Shdr *AnalyzeElf::GetDynamicSymbolSection()
{
    Elf32_Shdr*pShdr =  GetSection();
    for (int i =0;i<GetSectionCount();i++) {
        if(pShdr[i].sh_type == SHT_DYNSYM)
        {
            return &pShdr[i];
        }
    }
    return nullptr;
}


// 默认32位
int AnalyzeElf::GetProgramCount()
{
    if(m_isElf64)
        return  AnalyzeHeader64()->e_phnum;
    else
        return AnalyzeHeader32()->e_phnum;
}

int AnalyzeElf::GetSectionCount()
{
    if(m_isElf64)
        return  AnalyzeHeader64()->e_shnum;
    else
        return AnalyzeHeader32()->e_shnum;
}

int AnalyzeElf::GetDynamicSymbolCount()
{
    Elf32_Shdr*pShdr =  GetDynamicSymbolSection();
    if(pShdr == nullptr)
        return 0;
    return pShdr->sh_size / pShdr->sh_entsize;
}

int AnalyzeElf::GetSymbolCount()
{
    Elf32_Shdr*pShdr =  GetSymbolSection();
    if(pShdr == nullptr)
        return 0;
    return pShdr->sh_size / pShdr->sh_entsize;
}

addr_node AnalyzeElf::GetProgramInfo(int i,const QString &field_name)
{

    Elf32_Ehdr *pEhdr =  AnalyzeHeader32();
    Elf32_Phdr* phdr = (Elf32_Phdr*)(m_buff + pEhdr->e_phoff);
    addr_node node = {};
    node.field = field_name;

    if(field_name == "program_head")
    {
        int value = pEhdr->e_phoff;
        node.len = sizeof (Elf32_Phdr)* pEhdr->e_phnum;
        node.start_addr = pEhdr->e_phoff;
        node.value = value;
        return node;
    }

    else if(field_name == "p_head")
    {
        node.len = sizeof(Elf32_Phdr);
        node.start_addr = pEhdr->e_phoff + i * sizeof(Elf32_Phdr) ;
        return node;
    }

    else if(field_name == "p_type")
    {
        QString types[7] = {"PT_NULL","PT_LOAD",
                            "PT_DYNAMIC","PT_INTERP",
                            "PT_NOTE","PT_SHLIB",
                            "PT_PHDR"};
        uint32_t value = phdr[i].p_type;
        node.value = value;
        if(value < 7)
            node.info =   QString("%1 (%2)").arg(value,8,16,QLatin1Char('0')).arg(types[value]);
        else {
            node.info =   QString("%1 (%2)").arg(value,8,16,QLatin1Char('0')).arg("nothink");
        }
        node.len = sizeof(phdr[i].p_type);
        node.start_addr = pEhdr->e_phoff + i * sizeof(Elf32_Phdr) ;
        return node;

    }
    else if(field_name == "p_offset")
    {
        int value = phdr[i].p_offset;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.len = sizeof(phdr[i].p_offset);
        node.start_addr = pEhdr->e_phoff + i * sizeof(Elf32_Phdr)+ offsetof(Elf32_Phdr,p_offset) ;
        return node;
    }

    else if(field_name == "p_vaddr")
    {
        int value = phdr[i].p_vaddr;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.len = sizeof(phdr[i].p_vaddr);
        node.start_addr = pEhdr->e_phoff + i * sizeof(Elf32_Phdr)+ offsetof(Elf32_Phdr,p_vaddr) ;
        return node;
    }

    else if(field_name == "p_paddr")
    {
        int value = phdr[i].p_paddr;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.len = sizeof(phdr[i].p_paddr);
        node.start_addr = pEhdr->e_phoff + i * sizeof(Elf32_Phdr)+ offsetof(Elf32_Phdr,p_paddr) ;
        return node;
    }

    else if(field_name == "p_filesz")
    {
        int value = phdr[i].p_filesz;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.len = sizeof(phdr[i].p_filesz);
        node.start_addr = pEhdr->e_phoff + i * sizeof(Elf32_Phdr)+ offsetof(Elf32_Phdr,p_filesz) ;
        return node;
    }
    else if(field_name == "p_memsz")
    {
        int value = phdr[i].p_memsz;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.len = sizeof(phdr[i].p_memsz);
        node.start_addr = pEhdr->e_phoff + i * sizeof(Elf32_Phdr)+ offsetof(Elf32_Phdr,p_memsz) ;
        return node;
    }
    else if(field_name == "p_flags")
    {
        int value = phdr[i].p_flags;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.len = sizeof(phdr[i].p_flags);
        node.start_addr = pEhdr->e_phoff + i * sizeof(Elf32_Phdr)+ offsetof(Elf32_Phdr,p_flags) ;
        return node;
    }

    else if(field_name == "p_align")
    {
        int value = phdr[i].p_align;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.len = sizeof(phdr[i].p_align);
        node.start_addr = pEhdr->e_phoff + i * sizeof(Elf32_Phdr)+ offsetof(Elf32_Phdr,p_align) ;
        return node;
    }
    return  node;

}

addr_node AnalyzeElf::GetSectionInfo(int i, const QString &field_name)
{
    Elf32_Ehdr *pEhdr =  AnalyzeHeader32();
    Elf32_Shdr* pshdr = (Elf32_Shdr*)(m_buff + pEhdr->e_shoff);
    addr_node node = {};
    node.field = field_name;
    if(field_name == "section_head")
    {
        int value = pEhdr->e_phoff;
        node.len = sizeof (Elf32_Phdr)* pEhdr->e_shnum;
        node.start_addr = pEhdr->e_shoff;
        node.value = value;
        return node;
    }

    else if(field_name == "head")
    {
        uint32_t value = pshdr[i].sh_name;
        QString name = GetStringTableIndex(value);
        node.value = value;

        node.info =   QString("%1").arg(name);

        node.len = sizeof(Elf32_Shdr);
        node.start_addr = pEhdr->e_shoff + i * sizeof(Elf32_Shdr) ;
        return node;

    }

    else if(field_name == "sh_name")
    {
        uint32_t value = pshdr[i].sh_name;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.start_addr = (uint32_t)GetStringTableOffset() + value ;
        node.len = strlen((char*)((int)GetStringTableOffset() +(int)m_buff)+value) ;

        return node;

    }
    else if(field_name == "sh_type")
    {
        uint32_t value = pshdr[i].sh_type;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.start_addr = pEhdr->e_shoff + i * sizeof(Elf32_Shdr)+ offsetof(Elf32_Shdr,sh_type) ;
        node.len = sizeof(pshdr[i].sh_type); ;

        return node;
    }
    else if(field_name == "sh_flags")
    {
        uint32_t value = pshdr[i].sh_flags;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.start_addr = pEhdr->e_shoff + i * sizeof(Elf32_Shdr)+ offsetof(Elf32_Shdr,sh_flags) ;
        node.len = sizeof(pshdr[i].sh_flags); ;

        return node;
    }
    else if(field_name == "sh_flags")
    {
        uint32_t value = pshdr[i].sh_flags;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.start_addr = pEhdr->e_shoff + i * sizeof(Elf32_Shdr)+ offsetof(Elf32_Shdr,sh_flags) ;
        node.len = sizeof(pshdr[i].sh_flags); ;

        return node;
    }
    else if(field_name == "sh_addr")
    {
        uint32_t value = pshdr[i].sh_addr;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.start_addr = pEhdr->e_shoff + i * sizeof(Elf32_Shdr)+ offsetof(Elf32_Shdr,sh_addr) ;
        node.len = sizeof(pshdr[i].sh_addr); ;

        return node;
    }
    else if(field_name == "sh_offset")
    {
        uint32_t value = pshdr[i].sh_offset;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.start_addr = pEhdr->e_shoff + i * sizeof(Elf32_Shdr)+ offsetof(Elf32_Shdr,sh_offset) ;
        node.len = sizeof(pshdr[i].sh_offset); ;

        return node;
    }
    else if(field_name == "sh_size")
    {
        uint32_t value = pshdr[i].sh_offset;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.start_addr = pEhdr->e_shoff + i * sizeof(Elf32_Shdr)+ offsetof(Elf32_Shdr,sh_size) ;
        node.len = sizeof(pshdr[i].sh_size); ;

        return node;
    }
    else if(field_name == "sh_link")
    {
        uint32_t value = pshdr[i].sh_link;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.start_addr = pEhdr->e_shoff + i * sizeof(Elf32_Shdr)+ offsetof(Elf32_Shdr,sh_link) ;
        node.len = sizeof(pshdr[i].sh_link); ;

        return node;
    }
    else if(field_name == "sh_info")
    {
        uint32_t value = pshdr[i].sh_info;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.start_addr = pEhdr->e_shoff + i * sizeof(Elf32_Shdr)+ offsetof(Elf32_Shdr,sh_info) ;
        node.len = sizeof(pshdr[i].sh_info); ;

        return node;
    }

    else if(field_name == "sh_addralign")
    {
        uint32_t value = pshdr[i].sh_info;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.start_addr = pEhdr->e_shoff + i * sizeof(Elf32_Shdr)+ offsetof(Elf32_Shdr,sh_addralign) ;
        node.len = sizeof(pshdr[i].sh_addralign); ;

        return node;
    }
    else if(field_name == "sh_entsize")
    {
        uint32_t value = pshdr[i].sh_entsize;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.start_addr = pEhdr->e_shoff + i * sizeof(Elf32_Shdr)+ offsetof(Elf32_Shdr,sh_entsize) ;
        node.len = sizeof(pshdr[i].sh_entsize); ;

        return node;
    }

    return  node;
}

addr_node AnalyzeElf::GetSymbolInfo(int i, const QString &field_name)
{
    return GetSelectSymbolInfo(i,field_name,symbole_type::symbol);
}

addr_node AnalyzeElf::GetDynamicSymbolInfo(int i, const QString &field_name)
{
    return GetSelectSymbolInfo(i,field_name,symbole_type::dymamicsymbol);
}

addr_node AnalyzeElf::GetSelectSymbolInfo(int i, const QString &field_name, AnalyzeElf::symbole_type sym)
{
    Elf32_Shdr* pshdr = nullptr;
    if(sym == symbole_type::symbol)
        pshdr = GetSymbolSection();
    else {
        pshdr = GetDynamicSymbolSection();
    }

    Elf32_Sym* psym = (Elf32_Sym*)(pshdr->sh_offset + m_buff);

    addr_node node = {};
    node.field = field_name;
    if(field_name == "all_head")
    {
            node.len = GetSymbolCount()*sizeof(Elf32_Sym);
            node.start_addr = pshdr->sh_offset;
    }

    else if(field_name == "head")
    {
        uint32_t value = psym[i].st_value;
        QString name = GetSectionParseSymbolTableOffset(pshdr->sh_link,psym[i].st_name);
        node.value = value;
        node.info =   QString("%1").arg(name);
        node.len = sizeof(Elf32_Sym);
        node.start_addr = pshdr->sh_offset +i* sizeof(Elf32_Sym);
    }

    //    QString Names[6] = {"st_name","st_value","st_size","st_info",
    //                         "st_other","st_shndx"
    //                         };


    else if(field_name == "st_name")
    {
        uint32_t value = psym[i].st_name;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.start_addr =pshdr->sh_offset +i* sizeof(Elf32_Sym) + offsetof(Elf32_Sym,st_name);
        node.len = sizeof(psym[i].st_name); ;
    }
    else if(field_name == "st_value")
    {
        uint32_t value = psym[i].st_value;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.start_addr =pshdr->sh_offset +i* sizeof(Elf32_Sym)+ offsetof(Elf32_Sym,st_value);
        node.len = sizeof(psym[i].st_value); ;
    }
    else if(field_name == "st_size")
    {
        uint32_t value = psym[i].st_size;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.start_addr =pshdr->sh_offset +i* sizeof(Elf32_Sym)+ offsetof(Elf32_Sym,st_size);
        node.len = sizeof(psym[i].st_size); ;
    }
    else if(field_name == "st_info")
    {
        uint32_t value = psym[i].st_info;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.start_addr =pshdr->sh_offset +i* sizeof(Elf32_Sym)+ offsetof(Elf32_Sym,st_info);
        node.len = sizeof(psym[i].st_info); ;
    }
    else if(field_name == "st_other")
    {
        uint32_t value = psym[i].st_other;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.start_addr =pshdr->sh_offset +i* sizeof(Elf32_Sym)+ offsetof(Elf32_Sym,st_other);
        node.len = sizeof(psym[i].st_other); ;
    }
    else if(field_name == "st_shndx")
    {
        uint32_t value = psym[i].st_shndx;
        node.value = value;
        node.info =   QString("0x%1").arg(value,8,16,QLatin1Char('0'));
        node.start_addr =pshdr->sh_offset +i* sizeof(Elf32_Sym)+ offsetof(Elf32_Sym,st_shndx);
        node.len = sizeof(psym[i].st_other); ;
    }
    return  node;
}

QString AnalyzeElf::GetStringTableIndex(int offset)
{
    Elf32_Ehdr *pEhdr =  AnalyzeHeader32();
    Elf32_Shdr* pshdr = (Elf32_Shdr*)(m_buff + pEhdr->e_shoff);
    int index = pEhdr->e_shstrndx;
    char *pString = (char*)(pshdr[index].sh_offset + m_buff + offset);
    return  pString;
}

char *AnalyzeElf::GetStringTableOffset()
{
    Elf32_Ehdr *pEhdr =  AnalyzeHeader32();
    Elf32_Shdr* pshdr = (Elf32_Shdr*)(m_buff + pEhdr->e_shoff);
    int index = pEhdr->e_shstrndx;
    char *pString = (char*)pshdr[index].sh_offset ;
    return  pString;
}








