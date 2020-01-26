pragma solidity ^0.5.11;
import "Montagy.sol";

contract P3 {
    Montagy public server;
    constructor() public {
        server = Montagy(0xD068fcC44525569fB593189c8f22827cF0f50f3f);
    }
    function do_solve() public {
        server.solve('balsn');
    }
}
