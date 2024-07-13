// SPDX-License-Identifier: AGPL-3.0-or-later

/// usdai.t.sol -- tests for usdai.sol

// Copyright (C) 2015-2019  DappHub, LLC

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

pragma solidity ^0.6.12;

import "ds-test/test.sol";

import "../usdai.sol";

contract TokenUser {
    USDai  token;

    constructor(USDai token_) public {
        token = token_;
    }

    function doTransferFrom(address from, address to, uint amount)
        public
        returns (bool)
    {
        return token.transferFrom(from, to, amount);
    }

    function doTransfer(address to, uint amount)
        public
        returns (bool)
    {
        return token.transfer(to, amount);
    }

    function doApprove(address recipient, uint amount)
        public
        returns (bool)
    {
        return token.approve(recipient, amount);
    }

    function doAllowance(address owner, address spender)
        public
        view
        returns (uint)
    {
        return token.allowance(owner, spender);
    }

    function doBalanceOf(address who) public view returns (uint) {
        return token.balanceOf(who);
    }

    function doApprove(address guy)
        public
        returns (bool)
    {
        return token.approve(guy, uint(-1));
    }
    function doMint(uint wad) public {
        token.mint(address(this), wad);
    }
    function doBurn(uint wad) public {
        token.burn(address(this), wad);
    }
    function doMint(address guy, uint wad) public {
        token.mint(guy, wad);
    }
    function doBurn(address guy, uint wad) public {
        token.burn(guy, wad);
    }

}

interface Hevm {
    function warp(uint256) external;
}

contract USDaiTest is DSTest {
    uint constant initialBalanceThis = 1000;
    uint constant initialBalanceCal = 100;

    USDai token;
    Hevm hevm;
    address user1;
    address user2;
    address self;

    uint amount = 2;
    uint fee = 1;
    uint nonce = 0;
    uint deadline = 0;
    address cal = 0x549761f4f1326d01336aC17A77960FD422bD8b91;
    address del = 0xdd2d5D3f7f1b35b7A0601D6A00DbB7D44Af58479;

    // Values for the permit with no expiry
    bytes32 r = 0x166d2d87b57e7a4348afd6426a19f19285240531b384c60075033509adef8dc7;
    bytes32 s = 0x79418ce2841291b3e446ab908842147b43996c55ab8332bb4247aa55075a06ee;
    uint8 v = 28;

    // Values for the permit with expiry
    bytes32 _r = 0x52c13702258a7e9fda00535f1962aa84e5300a16d2cc02500e607f1bfb4c4c01;
    bytes32 _s = 0x421377e1cd232a6489c53254816155d3cc65217b7f0d352ab424989c5168eb18;
    uint8 _v = 27;



    function setUp() public {
        hevm = Hevm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
        hevm.warp(604411200);
        token = createToken();
        token.mint(address(this), initialBalanceThis);
        token.mint(cal, initialBalanceCal);
        user1 = address(new TokenUser(token));
        user2 = address(new TokenUser(token));
        self = address(this);
    }

    function createToken() internal returns (USDai) {
        return new USDai(99);
    }

    function testSetupPrecondition() public {
        assertEq(token.balanceOf(self), initialBalanceThis);
    }

    function testTransferCost() public logs_gas {
        token.transfer(address(0), 10);
    }

    function testAllowanceStartsAtZero() public logs_gas {
        assertEq(token.allowance(user1, user2), 0);
    }

    function testValidTransfers() public logs_gas {
        uint sentAmount = 250;
        emit log_named_address("token11111", address(token));
        token.transfer(user2, sentAmount);
        assertEq(token.balanceOf(user2), sentAmount);
        assertEq(token.balanceOf(self), initialBalanceThis - sentAmount);
    }

    function testFailWrongAccountTransfers() public logs_gas {
        uint sentAmount = 250;
        token.transferFrom(user2, self, sentAmount);
    }

    function testFailInsufficientFundsTransfers() public logs_gas {
        uint sentAmount = 250;
        token.transfer(user1, initialBalanceThis - sentAmount);
        token.transfer(user2, sentAmount + 1);
    }

    function testApproveSetsAllowance() public logs_gas {
        emit log_named_address("Test", self);
        emit log_named_address("Token", address(token));
        emit log_named_address("Me", self);
        emit log_named_address("User 2", user2);
        token.approve(user2, 25);
        assertEq(token.allowance(self, user2), 25);
    }

    function testChargesAmountApproved() public logs_gas {
        uint amountApproved = 20;
        token.approve(user2, amountApproved);
        assertTrue(TokenUser(user2).doTransferFrom(self, user2, amountApproved));
        assertEq(token.balanceOf(self), initialBalanceThis - amountApproved);
    }

    function testFailTransferWithoutApproval() public logs_gas {
        token.transfer(user1, 50);
        token.transferFrom(user1, self, 1);
    }

    function testFailChargeMoreThanApproved() public logs_gas {
        token.transfer(user1, 50);
        TokenUser(user1).doApprove(self, 20);
        token.transferFrom(user1, self, 21);
    }
    function testTransferFromSelf() public {
        token.transferFrom(self, user1, 50);
        assertEq(token.balanceOf(user1), 50);
    }
    function testFailTransferFromSelfNonArbitrarySize() public {
        // you shouldn't be able to evade balance checks by transferring
        // to yourself
        token.transferFrom(self, self, token.balanceOf(self) + 1);
    }
    function testMintself() public {
        uint mintAmount = 10;
        token.mint(address(this), mintAmount);
        assertEq(token.balanceOf(self), initialBalanceThis + mintAmount);
    }
    function testMintGuy() public {
        uint mintAmount = 10;
        token.mint(user1, mintAmount);
        assertEq(token.balanceOf(user1), mintAmount);
    }
    function testFailMintGuyNoAuth() public {
        TokenUser(user1).doMint(user2, 10);
    }
    function testMintGuyAuth() public {
        token.rely(user1);
        TokenUser(user1).doMint(user2, 10);
    }

    function testBurn() public {
        uint burnAmount = 10;
        token.burn(address(this), burnAmount);
        assertEq(token.totalSupply(), initialBalanceThis + initialBalanceCal - burnAmount);
    }
    function testBurnself() public {
        uint burnAmount = 10;
        token.burn(address(this), burnAmount);
        assertEq(token.balanceOf(self), initialBalanceThis - burnAmount);
    }
    function testBurnGuyWithTrust() public {
        uint burnAmount = 10;
        token.transfer(user1, burnAmount);
        assertEq(token.balanceOf(user1), burnAmount);

        TokenUser(user1).doApprove(self);
        token.burn(user1, burnAmount);
        assertEq(token.balanceOf(user1), 0);
    }
    function testBurnAuth() public {
        token.transfer(user1, 10);
        token.rely(user1);
        TokenUser(user1).doBurn(10);
    }
    function testBurnGuyAuth() public {
        token.transfer(user2, 10);
        //        token.rely(user1);
        TokenUser(user2).doApprove(user1);
        TokenUser(user1).doBurn(user2, 10);
    }

    function testFailUntrustedTransferFrom() public {
        assertEq(token.allowance(self, user2), 0);
        TokenUser(user1).doTransferFrom(self, user2, 200);
    }
    function testTrusting() public {
        assertEq(token.allowance(self, user2), 0);
        token.approve(user2, uint(-1));
        assertEq(token.allowance(self, user2), uint(-1));
        token.approve(user2, 0);
        assertEq(token.allowance(self, user2), 0);
    }
    function testTrustedTransferFrom() public {
        token.approve(user1, uint(-1));
        TokenUser(user1).doTransferFrom(self, user2, 200);
        assertEq(token.balanceOf(user2), 200);
    }
    function testApproveWillModifyAllowance() public {
        assertEq(token.allowance(self, user1), 0);
        assertEq(token.balanceOf(user1), 0);
        token.approve(user1, 1000);
        assertEq(token.allowance(self, user1), 1000);
        TokenUser(user1).doTransferFrom(self, user1, 500);
        assertEq(token.balanceOf(user1), 500);
        assertEq(token.allowance(self, user1), 500);
    }
    function testApproveWillNotModifyAllowance() public {
        assertEq(token.allowance(self, user1), 0);
        assertEq(token.balanceOf(user1), 0);
        token.approve(user1, uint(-1));
        assertEq(token.allowance(self, user1), uint(-1));
        TokenUser(user1).doTransferFrom(self, user1, 1000);
        assertEq(token.balanceOf(user1), 1000);
        assertEq(token.allowance(self, user1), uint(-1));
    }
    function testUSDaiAddress() public {
        //The usdai address generated by hevm
        //used for signature generation testing
        assertEq(address(token), address(0x11Ee1eeF5D446D07Cf26941C7F2B4B1Dfb9D030B));
    }



    function testTypehash() public {
        assertEq(token.PERMIT_TYPEHASH(), 0xea2aa0a1be11a07ed86d755c93467f4f82362b452371d1ba94d1715123511acb);
    }

    function testDomain_Separator() public {
        assertEq(token.DOMAIN_SEPARATOR(), 0x5d9a5722153f5207ba26baf8c65b8a2a403387c1739d5639e62853c46352f3e8);
    }






    function testPermit() public {
        uint expiry = 0;
        uint allowed = 1; // true as uint

        // Log the input values
        emit log_named_address("cal", cal);
        emit log_named_address("del", del);
        emit log_named_bytes32("r", r);
        emit log_named_bytes32("s", s);
        emit log_named_uint("v", v);
        emit log_named_uint("nonce", nonce);
        emit log_named_uint("expiry", expiry);

        // Calculate and log the DOMAIN_SEPARATOR
        bytes32 domainSeparator = token.DOMAIN_SEPARATOR();
        emit log_named_bytes32("DOMAIN_SEPARATOR", domainSeparator);

        // Calculate and log the PERMIT_TYPEHASH
        bytes32 permitTypehash = token.PERMIT_TYPEHASH();
        emit log_named_bytes32("PERMIT_TYPEHASH", permitTypehash);

        // Log individual components of the struct hash
        emit log_named_bytes32("permitTypehash", permitTypehash);
        emit log_named_address("cal", cal);
        emit log_named_address("del", del);
        emit log_named_uint("nonce", nonce);
        emit log_named_uint("expiry", expiry);
        emit log_named_uint("allowed", allowed);

        // Log abi.encode parameters for struct hash
        bytes memory encodedParams = abi.encode(
            permitTypehash,
            cal,
            del,
            nonce,
            expiry,
            allowed == 1
        );
        emit log_named_bytes("encodedParams", encodedParams);

        // Calculate and log the struct hash
        bytes32 structHash = keccak256(encodedParams);
        emit log_named_bytes32("structHash", structHash);

        // Log individual components of the permit hash
        emit log_named_bytes("prefix1", abi.encodePacked("\x19"));
        emit log_named_bytes("prefix2", abi.encodePacked("\x01"));
        emit log_named_bytes32("domainSeparator", domainSeparator);
        emit log_named_bytes32("structHash", structHash);

        // Log abi.encodePacked parameters for permit hash
        bytes memory packedParams = abi.encodePacked(
            "\x19\x01",
            domainSeparator,
            structHash
        );
        emit log_named_bytes("packedParams", packedParams);

        // Calculate and log the permit hash
        bytes32 expectedPermitHash = keccak256(packedParams);
        emit log_named_bytes32("Expected permit hash", expectedPermitHash);
        

        // Log the v, r, and s values used for signature
        emit log_named_uint("v", v);
        emit log_named_bytes32("r", r);
        emit log_named_bytes32("s", s);

        // Log intermediate steps for recovered address
        emit log_named_bytes("ecrecover params", abi.encodePacked(expectedPermitHash, v, r, s));
        address expectedRecoveredAddress = ecrecover(expectedPermitHash, v, r, s);
        emit log_named_address("Expected recovered address", expectedRecoveredAddress);

        // Call the permit function
        token.permit(cal, del, nonce, expiry, allowed == 1, v, r, s);

        // Log the results
        emit log_named_uint("Nonce after permit", token.nonces(cal));
        emit log_named_uint("Allowance after permit", token.allowance(cal, del));

        // Assert the values
        assertEq(token.allowance(cal, del), uint(-1));
        assertEq(token.nonces(cal), 1);
    }












    function testFailPermitAddress0() public {
        v = 0;
        token.permit(address(0), del, 0, 0, true, v, r, s);
    }












    function testPermitWithExpiry() public {
        uint expiry = 604411200 + 1 hours;
        uint allowed = 1; // true as uint

        assertEq(now, 604411200);

        // Log the input values
        emit log_named_address("cal", cal);
        emit log_named_address("del", del);
        emit log_named_bytes32("r", _r);
        emit log_named_bytes32("s", _s);
        emit log_named_uint("v", _v);
        emit log_named_uint("nonce", nonce);
        emit log_named_uint("expiry", expiry);

        // Calculate and log the DOMAIN_SEPARATOR
        bytes32 domainSeparator = token.DOMAIN_SEPARATOR();
        emit log_named_bytes32("DOMAIN_SEPARATOR", domainSeparator);

        // Calculate and log the PERMIT_TYPEHASH
        bytes32 permitTypehash = token.PERMIT_TYPEHASH();
        emit log_named_bytes32("PERMIT_TYPEHASH", permitTypehash);

        // Log individual components of the struct hash
        emit log_named_bytes32("permitTypehash", permitTypehash);
        emit log_named_address("cal", cal);
        emit log_named_address("del", del);
        emit log_named_uint("nonce", nonce);
        emit log_named_uint("expiry", expiry);
        emit log_named_uint("allowed", allowed);

        // Log abi.encode parameters for struct hash
        bytes memory encodedParams = abi.encode(
            permitTypehash,
            cal,
            del,
            nonce,
            expiry,
            allowed == 1
        );
        emit log_named_bytes("encodedParams", encodedParams);

        // Calculate and log the struct hash
        bytes32 structHash = keccak256(encodedParams);
        emit log_named_bytes32("structHash", structHash);

        // Log individual components of the permit hash
        emit log_named_bytes("prefix1", abi.encodePacked("\x19"));
        emit log_named_bytes("prefix2", abi.encodePacked("\x01"));
        emit log_named_bytes32("domainSeparator", domainSeparator);
        emit log_named_bytes32("structHash", structHash);

        // Log abi.encodePacked parameters for permit hash
        bytes memory packedParams = abi.encodePacked(
            "\x19\x01",
            domainSeparator,
            structHash
        );
        emit log_named_bytes("packedParams", packedParams);

        // Calculate and log the permit hash
        bytes32 expectedPermitHash = keccak256(packedParams);
        emit log_named_bytes32("Expected permit hash", expectedPermitHash);

        // Log the v, r, and s values used for signature
        emit log_named_uint("v", _v);
        emit log_named_bytes32("r", _r);
        emit log_named_bytes32("s", _s);

        // Log intermediate steps for recovered address
        emit log_named_bytes("ecrecover params", abi.encodePacked(expectedPermitHash, _v, _r, _s));
        address expectedRecoveredAddress = ecrecover(expectedPermitHash, _v, _r, _s);
        emit log_named_address("Expected recovered address", expectedRecoveredAddress);

        // Call the permit function
        token.permit(cal, del, nonce, expiry, allowed == 1, _v, _r, _s);

        // Log the results
        emit log_named_uint("Nonce after permit", token.nonces(cal));
        emit log_named_uint("Allowance after permit", token.allowance(cal, del));

        // Assert the values
        assertEq(token.allowance(cal, del), uint(-1));
        assertEq(token.nonces(cal), 1);
    }

    function testFailPermitWithExpiry() public {
        hevm.warp(now + 2 hours);
        assertEq(now, 604411200 + 2 hours);
        token.permit(cal, del, 0, 1, true, _v, _r, _s);
    }

    function testFailReplay() public {
        token.permit(cal, del, 0, 0, true, v, r, s);
        token.permit(cal, del, 0, 0, true, v, r, s);
    }

}
