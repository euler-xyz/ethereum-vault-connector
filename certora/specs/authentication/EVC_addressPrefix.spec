
methods{
    function getAddressPrefix(address) external returns (uint152) envfree;
    function haveCommonOwner(address, address) external returns (bool) envfree;
}

//check that to addresses with the same prefix also have a common owner
rule check_have_commonPrefix(){
    address x;
    address y;
    uint152 prefixX = getAddressPrefix(x);
    uint152 prefixY = getAddressPrefix(y);

    bool haveCommonOwner = haveCommonOwner(x,y);

    assert haveCommonOwner <=> prefixX == prefixY;
}
