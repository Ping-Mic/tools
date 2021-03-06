Hopper Script - Solve with angr
====

solve for `arg1`(`argv1`)
----
use [`(for arg1)` plugin](https://github.com/Ping-Mic/tools/blob/master/reversing/Hopper%20Scripts/Solve%20with%20angr%20(for%20arg1).py)

steps:

1. add `find` and `avoid` tags to basic blocks (procedures)
    * this `find`/`avoid` is same with angr's `find`/`avoid`
1. specify `input length` in a dialog box as __input length__
    * incorrect input length may results in _no solusions_
1. __(optional)__ you can tell flag format in a dialog box as __flag prefix__


solve for `stdin`
----
use [`(for stdin)` plugin](https://github.com/Ping-Mic/tools/blob/master/reversing/Hopper%20Scripts/Solve%20with%20angr%20(for%20stdin).py)

1. add `find` and `avoid` tags to basic blocks (procedures)
    * this `find`/`avoid` is same with angr's `find`/`avoid`
1. __(optional)__ specify `input length` in a dialog box as __input length__
    * incorrect input length may results in _no solusions_
1. __(optional)__ you can tell flag format in a dialog box as __flag prefix__



solve for variables in `.bss` section
----
use [`(for bss)` plugin](https://github.com/Ping-Mic/tools/blob/master/reversing/Hopper%20Scripts/Solve%20with%20angr%20(for%20bss).py)

steps:

1. find the variable which holds user input, and check the variable's symbol (label) name (or name it)
1. add `find` and `avoid` tags to basic blocks (procedures)
    * this `find`/`avoid` is same with angr's `find`/`avoid`
1. add label __sim_start__ to tell angr simulasion start address (_The address the state should start at instead of the entry point_)
    * label address is same with `addr` of angr.factory.blank_state
1. tell simbol name (you checked at step 1) in a dialog box as __target symbol__
1. specify `input length` in a dialog box as __input length__
    * incorrect input length may results in _no solusions_
1. __(option)__ you can tell flag format in a dialog box as __flag prefix__
