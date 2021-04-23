/* ------------------------------------------------------------------
 * ELF Symbol Rename Utility
 * ------------------------------------------------------------------ */

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Section list header */
#define OFFSETS_LIST_HEADER "    Offset      Size        Section name\n"

/* Swap bytes in 16-bit value.  */
#ifndef __bswap_constant_16
#define __bswap_constant_16(x) \
  ((__uint16_t) ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8)))
#endif

/* Swap bytes in 32-bit value.  */
#ifndef __bswap_constant_32
#define __bswap_constant_32(x) \
  ((((x) & 0xff000000u) >> 24) | (((x) & 0x00ff0000u) >> 8) \
   | (((x) & 0x0000ff00u) << 8) | (((x) & 0x000000ffu) << 24))
#endif

/* Swap bytes in 64-bit value.  */
#ifndef __bswap_constant_64
#define __bswap_constant_64(x) \
  ((((x) & 0xff00000000000000ull) >> 56) \
   | (((x) & 0x00ff000000000000ull) >> 40) \
   | (((x) & 0x0000ff0000000000ull) >> 24) \
   | (((x) & 0x000000ff00000000ull) >> 8) \
   | (((x) & 0x00000000ff000000ull) << 8) \
   | (((x) & 0x0000000000ff0000ull) << 24) \
   | (((x) & 0x000000000000ff00ull) << 40) \
   | (((x) & 0x00000000000000ffull) << 56))
#endif

/* Endian swap utils (host/elf) */
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define EH16(elf, X) ((elf)->big_endian?__bswap_constant_16((X)):(X))
#define EH32(elf, X) ((elf)->big_endian?__bswap_constant_32((X)):(X))
#define EH64(elf, X) ((elf)->big_endian?__bswap_constant_64((X)):(X))
#else
#define EH16(elf, X) ((elf)->big_endian?(X):__bswap_constant_16((X)))
#define EH32(elf, X) ((elf)->big_endian?(X):__bswap_constant_32((X)))
#define EH64(elf, X) ((elf)->big_endian?(X):__bswap_constant_64((X)))
#endif

/* Assertion Macros */
#define ASSERT_ELF_PTR(elf, ptr) if ((const unsigned char*) (ptr) >= ((elf)->buffer + (elf)->length)) \
    { \
        return -1; \
    }

#define ASSERT_ELF_OBJ(elf, ptr, size) if ((const unsigned char*) (ptr) >= ((elf)->buffer + (elf)->length) \
        || (const unsigned char*) (ptr) + size > ((elf)->buffer + (elf)->length)) \
    { \
        return -1; \
    }

#define ASSERT_ELF_STRING(elf, ptr) if ((const unsigned char*) (ptr) >= ((elf)->buffer + (elf)->length) \
        || strlen_ge((ptr), ((elf)->buffer + (elf)->length - (const unsigned char*) ptr))) \
    { \
        return -1; \
    }

/**
 * ELF binary structure
 */
struct elf_binary_t
{
    unsigned char *buffer;
    size_t length;
    int is_32_bit;
    int big_endian;
};

/**
 * ELF section list 32-bit
 */
struct sectlist_32_t
{
    const Elf32_Ehdr *eh;
    const Elf32_Shdr *sh;
    const unsigned char *shstrtab;
};

/**
 * ELF section list 64-bit
 */
struct sectlist_64_t
{
    const Elf64_Ehdr *eh;
    const Elf64_Shdr *sh;
    const unsigned char *shstrtab;
};

/**
 * ELF section info
 */
struct sectinfo_t
{
    size_t offset;
    size_t length;
};

/**
 * Check if string length is greater or equal
 */
static int strlen_ge ( const char *string, size_t length )
{
    const char *limit;
    limit = string + length;

    while ( *string )
    {
        if ( string == limit )
        {
            return 1;
        }
        string++;
    }
    return 0;
}

/**
 * Find ELF section list 32-bit
 */
static int find_sections_32 ( const struct elf_binary_t *elf, struct sectlist_32_t *list )
{
    const Elf32_Shdr *sh;

    list->eh = ( const Elf32_Ehdr * ) elf->buffer;
    ASSERT_ELF_OBJ ( elf, list->eh, sizeof ( Elf32_Ehdr ) );

    sh = ( const Elf32_Shdr * ) ( elf->buffer + EH32 ( elf, list->eh->e_shoff ) +
        EH16 ( elf, list->eh->e_shstrndx ) * sizeof ( Elf32_Shdr ) );
    ASSERT_ELF_OBJ ( elf, sh, sizeof ( Elf32_Shdr ) );

    list->shstrtab = elf->buffer + EH32 ( elf, sh->sh_offset );
    ASSERT_ELF_PTR ( elf, list->shstrtab );

    list->sh = ( const Elf32_Shdr * ) ( elf->buffer + EH32 ( elf, list->eh->e_shoff ) );
    ASSERT_ELF_PTR ( elf, list->sh );

    return 0;
}

/**
 * Find ELF section list 64-bit
 */
static int find_sections_64 ( const struct elf_binary_t *elf, struct sectlist_64_t *list )
{
    const Elf64_Shdr *sh;

    list->eh = ( const Elf64_Ehdr * ) elf->buffer;
    ASSERT_ELF_OBJ ( elf, list->eh, sizeof ( Elf64_Ehdr ) );

    sh = ( const Elf64_Shdr * ) ( elf->buffer + EH64 ( elf, list->eh->e_shoff ) +
        EH16 ( elf, list->eh->e_shstrndx ) * sizeof ( Elf64_Shdr ) );
    ASSERT_ELF_OBJ ( elf, sh, sizeof ( Elf64_Shdr ) );

    list->shstrtab = elf->buffer + EH64 ( elf, sh->sh_offset );
    ASSERT_ELF_PTR ( elf, list->shstrtab );

    list->sh = ( const Elf64_Shdr * ) ( elf->buffer + EH64 ( elf, list->eh->e_shoff ) );
    ASSERT_ELF_PTR ( elf, list->sh );

    return 0;
}

/*
 * Print ELF sections 32-bit
 */
static int print_sections_32 ( const struct elf_binary_t *elf )
{
    uint16_t i;
    uint16_t n;
    const char *sh_name;
    const Elf32_Shdr *sh;
    struct sectlist_32_t list;

    /* Find ELF sections */
    if ( find_sections_32 ( elf, &list ) < 0 )
    {
        return -1;
    }

    /* Print sections list header */
    putchar ( '\n' );
    printf ( OFFSETS_LIST_HEADER );

    /* List non-empty sections */
    for ( n = EH16 ( elf, list.eh->e_shnum ), i = 0; i < n; i++ )
    {
        sh = list.sh + i;
        ASSERT_ELF_OBJ ( elf, sh, sizeof ( Elf32_Shdr ) );
        sh_name = ( const char * ) ( list.shstrtab + EH32 ( elf, sh->sh_name ) );
        ASSERT_ELF_STRING ( elf, sh_name );

        if ( EH64 ( elf, sh[i].sh_size ) && *sh_name )
        {
            printf ( " -- %.8lu    %.8lu    %s\n", ( unsigned long ) EH32 ( elf, sh[i].sh_offset ),
                ( unsigned long ) EH32 ( elf, sh[i].sh_size ), sh_name );
        }
    }

    putchar ( '\n' );

    return 0;
}

/*
 * Print ELF sections 64-bit
 */
static int print_sections_64 ( const struct elf_binary_t *elf )
{
    uint16_t i;
    uint16_t n;
    const char *sh_name;
    const Elf64_Shdr *sh;
    struct sectlist_64_t list;

    /* Find ELF sections */
    if ( find_sections_64 ( elf, &list ) < 0 )
    {
        return -1;
    }

    /* Print sections list header */
    putchar ( '\n' );
    printf ( OFFSETS_LIST_HEADER );

    /* List non-empty sections */
    for ( n = EH16 ( elf, list.eh->e_shnum ), i = 0; i < n; i++ )
    {
        sh = list.sh + i;
        ASSERT_ELF_OBJ ( elf, sh, sizeof ( Elf64_Shdr ) );
        sh_name = ( const char * ) ( list.shstrtab + EH32 ( elf, sh->sh_name ) );
        ASSERT_ELF_STRING ( elf, sh_name );

        if ( EH64 ( elf, sh[i].sh_size ) && *sh_name )
        {
            printf ( " -- %.8lu    %.8lu    %s\n", ( unsigned long ) EH64 ( elf, sh[i].sh_offset ),
                ( unsigned long ) EH64 ( elf, sh[i].sh_size ), sh_name );
        }
    }

    putchar ( '\n' );

    return 0;
}

/*
 * Print ELF sections
 */
static int print_sections ( const struct elf_binary_t *elf )
{
    return elf->is_32_bit ? print_sections_32 ( elf ) : print_sections_64 ( elf );
}

/*
 * Find ELF section by name 32-bit
 */
static int find_section_32 ( const struct elf_binary_t *elf, const char *name,
    struct sectinfo_t *result )
{
    uint16_t i;
    uint16_t n;
    const char *sh_name;
    const Elf32_Shdr *sh;
    struct sectlist_32_t list;

    /* Find ELF sections */
    if ( find_sections_32 ( elf, &list ) < 0 )
    {
        return -1;
    }

    /* List non-empty sections */
    for ( n = EH16 ( elf, list.eh->e_shnum ), i = 0; i < n; i++ )
    {
        sh = list.sh + i;
        ASSERT_ELF_OBJ ( elf, sh, sizeof ( Elf32_Shdr ) );
        sh_name = ( const char * ) ( list.shstrtab + EH32 ( elf, sh->sh_name ) );
        ASSERT_ELF_STRING ( elf, sh_name );

        if ( !strcmp ( sh_name, name ) )
        {
            result->offset = EH32 ( elf, sh->sh_offset );
            result->length = EH32 ( elf, sh->sh_size );
            return 0;
        }
    }

    return -1;
}

/*
 * Find ELF section by name 64-bit
 */
static int find_section_64 ( const struct elf_binary_t *elf, const char *name,
    struct sectinfo_t *result )
{
    uint16_t i;
    uint16_t n;
    const char *sh_name;
    const Elf64_Shdr *sh;
    struct sectlist_64_t list;

    /* Find ELF sections */
    if ( find_sections_64 ( elf, &list ) < 0 )
    {
        return -1;
    }

    /* List non-empty sections */
    for ( n = EH16 ( elf, list.eh->e_shnum ), i = 0; i < n; i++ )
    {
        sh = list.sh + i;
        ASSERT_ELF_OBJ ( elf, sh, sizeof ( Elf32_Shdr ) );
        sh_name = ( const char * ) ( list.shstrtab + EH32 ( elf, sh->sh_name ) );
        ASSERT_ELF_STRING ( elf, sh_name );

        if ( !strcmp ( sh_name, name ) )
        {
            result->offset = EH64 ( elf, sh->sh_offset );
            result->length = EH64 ( elf, sh->sh_size );
            return 0;
        }
    }

    return -1;
}

/*
 * Find ELF section by name
 */
static int find_section ( const struct elf_binary_t *elf, const char *name,
    struct sectinfo_t *result )
{
    return elf->is_32_bit ? find_section_32 ( elf, name, result ) : find_section_64 ( elf, name,
        result );
}

/**
 * Find ELF symbol offset 32-bit
 */
static int find_symbol_offset_32 ( const struct elf_binary_t *elf,
    const struct sectinfo_t *sym_sect, const struct sectinfo_t *str_sect, const char *name,
    size_t *result )
{
    size_t i;
    size_t n;
    const char *sym_name;
    Elf32_Sym *symbols;

    symbols = ( Elf32_Sym * ) ( elf->buffer + sym_sect->offset );
    ASSERT_ELF_PTR ( elf, symbols );

    for ( n = sym_sect->length / sizeof ( Elf32_Sym ), i = 0; i < n; i++ )
    {
        sym_name =
            ( const char * ) ( elf->buffer + str_sect->offset + EH32 ( elf, symbols[i].st_name ) );
        ASSERT_ELF_STRING ( elf, sym_name );

        if ( !strcmp ( sym_name, name ) )
        {
            *result = i;
            return 0;
        }
    }

    return -1;
}

/**
 * Find ELF symbol offset 64-bit
 */
static int find_symbol_offset_64 ( const struct elf_binary_t *elf,
    const struct sectinfo_t *sym_sect, const struct sectinfo_t *str_sect, const char *name,
    size_t *result )
{
    size_t i;
    size_t n;
    const char *sym_name;
    Elf64_Sym *symbols;

    symbols = ( Elf64_Sym * ) ( elf->buffer + sym_sect->offset );
    ASSERT_ELF_PTR ( elf, symbols );

    for ( n = sym_sect->length / sizeof ( Elf64_Sym ), i = 0; i < n; i++ )
    {
        sym_name =
            ( const char * ) ( elf->buffer + str_sect->offset + EH64 ( elf, symbols[i].st_name ) );
        ASSERT_ELF_STRING ( elf, sym_name );

        if ( !strcmp ( sym_name, name ) )
        {
            *result = i;
            return 0;
        }
    }

    return -1;
}

/*
 * Find ELF symbol offset
 */
static int find_symbol_offset ( const struct elf_binary_t *elf, const struct sectinfo_t *sym_sect,
    const struct sectinfo_t *str_sect, const char *name, size_t *result )
{
    return elf->is_32_bit ? find_symbol_offset_32 ( elf, sym_sect, str_sect, name, result )
        : find_symbol_offset_64 ( elf, sym_sect, str_sect, name, result );
}

/*
 * Rename ELF symbol 32-bit
 */
static int rename_symbol_32 ( struct elf_binary_t *elf, const struct sectinfo_t *sym_sect,
    const struct sectinfo_t *str_sect, size_t symbol_offset, const char *new_name )
{
    size_t nsymbols;
    size_t length;
    char *symbol_name;
    Elf32_Sym *symbols;

    symbols = ( Elf32_Sym * ) ( elf->buffer + sym_sect->offset );
    ASSERT_ELF_PTR ( elf, symbols );
    nsymbols = sym_sect->length / sizeof ( Elf32_Sym );

    if ( symbol_offset >= nsymbols )
    {
        return -1;
    }

    symbol_name =
        ( char * ) ( elf->buffer + str_sect->offset + EH32 ( elf,
            symbols[symbol_offset].st_name ) );
    ASSERT_ELF_STRING ( elf, symbol_name );

    length = strlen ( new_name );
    if ( strlen ( symbol_name ) != length )
    {
        return -1;
    }

    memcpy ( symbol_name, new_name, length );
    return 0;
}

/*
 * Rename ELF symbol 64-bit
 */
static int rename_symbol_64 ( struct elf_binary_t *elf, const struct sectinfo_t *sym_sect,
    const struct sectinfo_t *str_sect, size_t symbol_offset, const char *new_name )
{
    size_t nsymbols;
    size_t length;
    char *symbol_name;
    Elf64_Sym *symbols;

    symbols = ( Elf64_Sym * ) ( elf->buffer + sym_sect->offset );
    ASSERT_ELF_PTR ( elf, symbols );
    nsymbols = sym_sect->length / sizeof ( Elf64_Sym );

    if ( symbol_offset >= nsymbols )
    {
        return -1;
    }

    symbol_name =
        ( char * ) ( elf->buffer + str_sect->offset + EH64 ( elf,
            symbols[symbol_offset].st_name ) );
    ASSERT_ELF_STRING ( elf, symbol_name );

    length = strlen ( new_name );
    if ( strlen ( symbol_name ) != length )
    {
        return -1;
    }

    memcpy ( symbol_name, new_name, length );
    return 0;
}

/*
 * Rename ELF symbol name
 */
static int rename_symbol ( struct elf_binary_t *elf, const struct sectinfo_t *sym_sect,
    const struct sectinfo_t *str_sect, size_t symbol_offset, const char *new_name )
{
    return elf->is_32_bit ? rename_symbol_32 ( elf, sym_sect, str_sect, symbol_offset,
        new_name ) : rename_symbol_64 ( elf, sym_sect, str_sect, symbol_offset, new_name );
}

/**
 * Rename ELF symbol task
 */
static int rename_task_in ( struct elf_binary_t *elf, const struct sectinfo_t *sym_sect,
    const struct sectinfo_t *str_sect, const char *symbol_cur_name, const char *symbol_new_name,
    size_t *symbol_offset )
{
    /* Find symbol offset */
    if ( find_symbol_offset ( elf, sym_sect, str_sect, symbol_cur_name, symbol_offset ) < 0 )
    {
        fprintf ( stderr, "symbol %s not found!\n", symbol_cur_name );
        return -1;
    }

    /* Swap symbol names */
    if ( rename_symbol ( elf, sym_sect, str_sect, *symbol_offset, symbol_new_name ) < 0 )
    {
        fprintf ( stderr, "unable to rename symbol %s!\n", symbol_cur_name );
        return -1;
    }

    return 0;
}

/**
 * Rename ELF symbol task
 */
static int rename_task ( struct elf_binary_t *elf, const char *symbol_cur_name,
    const char *symbol_new_name )
{
    int done = 0;
    size_t symbol_offset;
    struct sectinfo_t sym_sect;
    struct sectinfo_t str_sect;

    /* Symbol names must be the same length */
    if ( strlen ( symbol_cur_name ) != strlen ( symbol_new_name ) )
    {
        fprintf ( stderr, "symbols (%s) and (%s) are not the same length!\n",
            symbol_cur_name, symbol_new_name );
        return -1;
    }

    /* Lookup symbols and strings sections */
    if ( find_section ( elf, ".symtab", &sym_sect ) >= 0
        && find_section ( elf, ".strtab", &str_sect ) >= 0 )
    {
        if ( rename_task_in ( elf, &sym_sect, &str_sect, symbol_cur_name, symbol_new_name,
                &symbol_offset ) >= 0 )
        {
            printf ( "+%.4lu %s => %s (.symtab and .strtab)\n", ( unsigned long ) symbol_offset,
                symbol_cur_name, symbol_new_name );
            done = 1;
        }
    }

    if ( find_section ( elf, ".dynsym", &sym_sect ) >= 0
        && find_section ( elf, ".dynstr", &str_sect ) >= 0 )
    {
        if ( rename_task_in ( elf, &sym_sect, &str_sect, symbol_cur_name, symbol_new_name,
                &symbol_offset ) >= 0 )
        {
            printf ( "+%.4lu %s => %s (.dynsym and .dynstr)\n", ( unsigned long ) symbol_offset,
                symbol_cur_name, symbol_new_name );
            done = 1;
        }
    }

    /* Check for successful attempt */
    if ( !done )
    {
        return -1;
    }

    return 0;
}

/**
 * Program startup
 */
int main ( int argc, char *argv[] )
{
    int status = 0;
    int fd;
    int finish = 0;
    size_t len;
    const char *begin;
    const char *end;
    Elf32_Ehdr *teh;
    struct elf_binary_t elf;
    const char *file_path;
    const char *replace_tab;
    char symbol_cur_name[512];
    char symbol_new_name[512];

    /* Show program banner */
    printf ( "ELF Symbol Rename Utility - ver. 1.0.20\n" );

    /* Check arguments count */
    if ( argc != 3 )
    {
        fprintf ( stderr, "\n  usage: symrename elf-binary cur-name=new-name,...\n\n" );
        return 1;
    }

    /* Get command line arguments */
    file_path = argv[1];
    replace_tab = argv[2];

    /* Prepare ELF binary info */
    memset ( &elf, '\0', sizeof ( elf ) );

    /* Open elf binary file */
    if ( ( fd = open ( file_path, O_RDWR ) ) < 0 )
    {
        perror ( file_path );
        goto error;
    }

    /* Measure ELF binary file length */
    elf.length = lseek ( fd, 0, SEEK_END );

    /* Check ELF binary file length */
    if ( elf.length < sizeof ( Elf32_Ehdr ) )
    {
        fprintf ( stderr, "elf binary is too small.\n" );
        goto error;
    }

    /*
     * Map data from the file into our memory for read & write.
     * Use MAP_SHARED for Persistent Memory so that stores go
     * directly to the PM and are globally visible.
     */
    if ( ( elf.buffer =
            ( unsigned char * ) mmap ( NULL, elf.length, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                0 ) ) == MAP_FAILED )
    {
        perror ( "mmap" );
        close ( fd );
        goto error;
    }

    /* Don't need the fd anymore, everything done above */
    close ( fd );

    teh = ( Elf32_Ehdr * ) elf.buffer;

    /* determinate whether ELF binary is 32 bit or 64 bit */
    if ( teh->e_ident[EI_CLASS] == ELFCLASS32 )
    {
        elf.is_32_bit = 1;

    } else if ( teh->e_ident[EI_CLASS] == ELFCLASS64 )
    {
        elf.is_32_bit = 0;

    } else
    {
        fprintf ( stderr, "unknown binary bitness.\n" );
        goto error;
    }

    /* determinate whether ELF binary is big or little endian */
    if ( teh->e_ident[EI_DATA] == ELFDATA2MSB )
    {
        elf.big_endian = 1;

    } else if ( teh->e_ident[EI_DATA] == ELFDATA2LSB )
    {
        elf.big_endian = 0;

    } else
    {
        fprintf ( stderr, "unknown binary endian!\n" );
        goto error;
    }

    /* Summary ELF binary */
    printf ( "\n    ELF Summary\n" );
    printf ( " -- length : %lu bytes\n", ( unsigned long ) elf.length );
    printf ( " -- type   : %u-bit\n", elf.is_32_bit ? 32 : 64 );
    printf ( " -- arch   : 0x%.2x\n", teh->e_machine );
    printf ( " -- endian : %s\n", elf.big_endian ? "big" : "little" );

    /* Print ELF sections */
    if ( print_sections ( &elf ) < 0 )
    {
        fprintf ( stderr, "warning: failed to print sections!\n" );
    }

    /* Rename symbols */
    begin = replace_tab;
    while ( !finish )
    {
        if ( !( end = strchr ( begin, '=' ) ) )
        {
            break;
        }

        if ( ( len = end - begin ) >= sizeof ( symbol_cur_name ) )
        {
            fprintf ( stderr, "symbol name near %s is too long!\n", begin );
            goto error;
        }

        memcpy ( symbol_cur_name, begin, len );
        symbol_cur_name[len] = '\0';

        begin = end + 1;

        if ( !( end = strchr ( begin, ',' ) ) )
        {
            end = replace_tab + strlen ( replace_tab );
            finish = 1;
        }

        if ( ( len = end - begin ) >= sizeof ( symbol_cur_name ) )
        {
            fprintf ( stderr, "symbol name near %s is too long!\n", begin );
            goto error;
        }

        memcpy ( symbol_new_name, begin, len );
        symbol_new_name[len] = '\0';

        if ( rename_task ( &elf, symbol_cur_name, symbol_new_name ) < 0 )
        {
            goto error;
        }

        if ( !finish )
        {
            begin = end + 1;
        }
    }

    /*
     * The above stores may or may not be sitting in cache at
     * this point, depending on other system activity causing
     * cache pressure.  Force the change to be durable (flushed
     * all the say to the Persistent Memory) using msync().
     */
    if ( msync ( ( void * ) elf.buffer, elf.length, MS_SYNC ) < 0 )
    {
        perror ( "msync" );
        goto error;
    }

    /* Show progress */
    fprintf ( stderr, "operation successful.\n" );
    goto exit;

  error:

    fprintf ( stderr, "operation failed.\n" );
    status = 1;

  exit:

    /* Free memory map */
    if ( elf.buffer )
    {
        munmap ( elf.buffer, elf.length );
    }

    return status;
}
