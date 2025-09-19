// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PassportRegistry {
    struct Passport {
        string fullName;
        string passportId;
        string dateOfBirth;
        string nationality;
        string expiryDate;
        string ipfsCID;
        bool exists;
    }

    mapping(address => Passport) private passports;

    event PassportIssued(
        address indexed owner,
        string passportId,
        string expiryDate,
        string ipfsCID
    );

    function issuePassport(
        string memory _fullName,
        string memory _passportId,
        string memory _dateOfBirth,
        string memory _nationality,
        string memory _expiryDate,
        string memory _ipfsCID
    ) public {
        require(!passports[msg.sender].exists, "Passport already exists");
        passports[msg.sender] = Passport(
            _fullName,
            _passportId,
            _dateOfBirth,
            _nationality,
            _expiryDate,
            _ipfsCID,
            true
        );
        emit PassportIssued(msg.sender, _passportId, _expiryDate, _ipfsCID);
    }

    function getPassport(address user) public view returns (
        string memory fullName,
        string memory passportId,
        string memory dateOfBirth,
        string memory nationality,
        string memory expiryDate,
        string memory ipfsCID
    ) {
        require(passports[user].exists, "No passport found");
        Passport memory p = passports[user];
        return (
            p.fullName,
            p.passportId,
            p.dateOfBirth,
            p.nationality,
            p.expiryDate,
            p.ipfsCID
        );
    }
}