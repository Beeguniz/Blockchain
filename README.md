AppMaHoa có source code là file AES_update.py
Chạy AppMaHoa để mã hóa file json thành file .bin
file cid.js để chuyển đổi file đã mã hóa thành CID thông qua web3 (IPFS)
Dùng lệnh cd ./ipfs-tool để đến thư mục chạy file cid.js lấy CID
Để chạy file cid.js thì sử dụng câu lệnh này dưới terminal: node cid.js "D:\NCKH\DFL\data_encrypted.bin" "did:key:...SPACE_DID..."
*Lưu ý* thay "D:\NCKH\DFL\data_encrypted.bin" bằng đường dẫn file .bin , thay "did:key:...SPACE_DID..." bằng id của tài khoản trên web3.storage
Etherum.sol có thể lưu thông tin cá nhân cơ bản và CID
