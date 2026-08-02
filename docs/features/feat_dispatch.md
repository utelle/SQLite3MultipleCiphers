---
layout: default
title: Use of dispatch tables
parent: Features
nav_order: 3
---
# Use of dispatch tables
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Introduction

_SQLite3 Multiple Ciphers_ is designed as a **drop-in replacement for the original SQLite library**. Therefore, it intentionally exports the standard `sqlite3_*` API and is intended to provide the SQLite implementation used by the application.

The SQLite documentation recommends that only **one SQLite implementation** should exist within a process (see section [Multiple copies of _SQLite_ linked into the same application](https://sqlite.org/howtocorrupt.html#multiple_copies_of_sqlite_linked_into_the_same_application) of the SQLite documentation about [How to corrupt an SQLite database file](https://sqlite.org/howtocorrupt.html)). SQLite maintains process-wide global state (such as memory management, mutex configuration, VFS registrations, extension handling, and initialization state) that is not designed to be duplicated across multiple independent SQLite builds.

For this reason, using _SQLite3 Multiple Ciphers_ together with other SQLite implementations in the same process can lead to unpredictable behavior. Examples include:

- libraries that embed their own SQLite build for internal use,
- libraries that export the standard `sqlite3_*` symbols,
- applications that intentionally load multiple SQLite variants,
- components that link against a system-provided SQLite implementation while the application uses _SQLite3 Multiple Ciphers_ as a replacement.

A native component may embed SQLite without intending to expose SQLite as part of its public API. However, if the embedded SQLite symbols are not hidden or renamed during the build process, they can become visible to the entire process and conflict with other SQLite implementations.

The presence of multiple SQLite implementations can cause problems even if they use the same SQLite version. Different compile-time options, enabled extensions, patches, or build configurations can result in incompatible behavior. For example, one SQLite build may include extensions such as FTS5, JSON support, ICU integration, or encryption-related functionality, while another build does not.

When multiple SQLite implementations are present, symbol resolution depends on the platform, linker, loader, and application configuration. As a result, it may not be predictable which implementation is actually used at runtime. Typical symptoms include:

- encryption-related PRAGMAs such as `PRAGMA key` or `PRAGMA cipher` having no effect,
- encrypted databases failing to open with errors such as *"file is not a database"*,
- missing SQLite extensions or compile-time features,
- subtle runtime failures caused by different SQLite versions or build configurations.

Platform-specific linker options (such as `ForceLoad` on iOS) may influence which SQLite implementation is selected in a particular application. However, such settings only affect symbol availability or resolution in a specific build scenario. They do not solve the underlying problem of multiple competing SQLite implementations within the same process and may have unintended effects on other components.

It is therefore the responsibility of the application developer to ensure that the application uses a consistent SQLite configuration and to avoid combining components that provide incompatible SQLite implementations.

## Hiding external symbols

If a component uses SQLite only as an internal implementation detail, it should ideally hide or rename its SQLite symbols so that they do not conflict with the SQLite implementation chosen by the application.

The likelihood of symbol conflicts depends on the native platform and on how the involved libraries are built.

On some platforms, such as Windows, symbols in dynamic libraries (DLLs) are usually exported only when they are explicitly marked for export. This reduces the chance that internal implementation symbols accidentally become globally visible.

However, similar conflicts can still occur when static libraries are linked into the same application. If multiple static libraries contain identical global symbols, the final result depends on linker behavior, library order, and build settings.

On platforms where native symbols are more commonly visible by default, accidentally exporting internal SQLite symbols is easier and can lead to conflicts with other SQLite implementations in the same process.

## Dispatch tables

_SQLite_ itself already brings a large part of the solution with it in the form of the header file `sqlite3ext.h`, which provides SQLite extensions with a _dispatch table_ containing pointers to most API functions. 

So, one way of avoiding the linker and runtime issues mentioned above is to extend _SQLite's_ concept of the dispatch table for extensions. The idea is actually:

1. Make **all** SQLite API functions static,
2. Make use of the already available dispatch tabel of SQLite (covering all functions defined in `sqlite3ext.h`),
3. Create a _second_ dispatch table containing the API functions that are not covered by those defined in `sqlite3ext.h`,
4. Create a _third_ dispatch table containing the API functions specific to _SQLite3 Multiple Ciphers_,
5. Provide global pointers to the _dispatch tables_,
6. Extend the mapping concept of `sqlite3ext.h` to the additional dispatch tables,
7. Optionally make the external names of dispatch tables configurable, so that name clashes can be avoided easily.

## How to use dispatch tables

Starting with _SQLite3 Multiple Ciphers_ version [2.5.0](https://github.com/utelle/SQLite3MultipleCiphers/releases/tag/v2.5.0) a simple approach to use the concept of _dispatch tables_ is provided by adding 2 compile time symbols, namely `SQLITE3MC_USE_DISPATCH_TABLE` and `SQLITE3MC_API_TABLE_PREFIX`:

- Symbol `SQLITE3MC_USE_DISPATCH_TABLE` allows to effectively hide all SQLite API functions' symbols from the linker by establishing dispatch tables for calling the SQLite API functions;
- Symbol `SQLITE3MC_API_TABLE_PREFIX` optionally allows to adjust the external names of the dispatch tables, so that even 2 instances of _SQLite3MC_ could operate in parallel, as long as they don't access the same database file(s). If the symbol is not defined, the default prefix `sqlite3mc` will be used.

Applying the dispatch table concept to an application requires the following steps:

1. Compile _SQLite3 Multiple Ciphers_ (either from the repository sources or the source amalgamation) specifying the symbol `SQLITE3MC_USE_DISPATCH_TABLE`in addition to any other compile time options; optionally define also the symbol `SQLITE3MC_API_TABLE_PREFIX` with a name suitable for your project;
2. Compile your own application (in which you use the header file `sqlite3mc.h` resp. `sqlite3mc_amalgamation.h`, if you use the source amalgamation) with the additional symbol `SQLITE3MC_USE_DISPATCH_TABLE` defined. If you used symbol `SQLITE3MC_API_TABLE_PREFIX` for compiling _SQLite3 Multiple Ciphers_ use it with exactly the same value for compiling your own application.

And that's all there is to it. The rest of the application's source code that uses _SQLite_ remains completely unchanged.
