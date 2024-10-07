# E8Patch

E8Patch is a static binary rewriting tool for replacing function calls.

Features:  
* **Compatible**: The rewritten binary is a drop-in replacement of the
 original, maintaining its structure without adding dependencies.
* **Intuitive**: Easy to use with patches written in C as normal functions

Just like [e9patch](https://github.com/GJDuck/e9patch) is named so after the relative jump instruction identifier on x86, e8 is the relative call instruction identifier.

## Usage
`e8patch target patch.c -o patched`

Patch example:
```c
int f2();
#pragma replace f2 old=f2 new:f2_plus_10
int f2_plus_10()
{
  return f2() + 10;
}
```

## Examples
Test cases can be used as an example.

## Docs

Argparse's help menu:
`python src -h`

Patch replacement instructions:
```c
#pragma replace <target> [old=ref_to_old_implementation] new=<name_of_new_function>
```

## Testing
Each test case contains:
- target binary source code
- patch
- patched source code
- a regex to match the expected output

## Libraries
Uses [Capstone](https://www.capstone-engine.org/) and a fork of [ELF Esteem](https://github.com/CristiSima/elfesteem) mantined mantained by [LRGH](https://github.com/LRGH/elfesteem)

## License

This software has been released under the GNU General Public License (GPL) Version 2.0.

