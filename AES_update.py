# crewvn_encryptor.py
# GUI AES JSON Encryptor with Drag-and-Drop (tkinterdnd2 optional)
import json
import threading
from pathlib import Path
import tkinter as tk
from tkinter import Tk, StringVar, BooleanVar, filedialog, messagebox
from tkinter import ttk

# --- Optional Drag & Drop support ---
DNDSUPPORTED = True
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except Exception:
    DNDSUPPORTED = False
    TkinterDnD = None
    DND_FILES = None

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

APP_TITLE = "Crewvn AES JSON Encryptor"
DEFAULT_ITER = 1_000_000
SALT_LEN = 16
IV_LEN = 16

def derive_key(password: str, salt: bytes, key_len: int, iterations: int) -> bytes:
    if not password:
        raise ValueError("Mật khẩu rỗng.")
    if iterations < 50_000:
        raise ValueError("Số vòng PBKDF2 quá thấp (>= 50,000).")
    return PBKDF2(password, salt, dkLen=key_len, count=iterations)

def encrypt_json_file(input_path: Path, output_path: Path, password: str, key_len_bytes: int, iterations: int):
    with input_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")

    salt = get_random_bytes(SALT_LEN)
    key = derive_key(password, salt, key_len_bytes, iterations)
    cipher = AES.new(key, AES.MODE_CBC)
    pt_padded = pad(plaintext, AES.block_size)
    ct = cipher.encrypt(pt_padded)

    blob = salt + cipher.iv + ct
    with output_path.open("wb") as f:
        f.write(blob)

def decrypt_blob_to_json(input_path: Path, output_path: Path, password: str, key_len_bytes: int, iterations: int):
    blob = input_path.read_bytes()
    if len(blob) < SALT_LEN + IV_LEN + 1:
        raise ValueError("Dữ liệu quá ngắn (thiếu salt/IV).")
    salt = blob[:SALT_LEN]
    iv = blob[SALT_LEN:SALT_LEN+IV_LEN]
    ct = blob[SALT_LEN+IV_LEN:]

    key = derive_key(password, salt, key_len_bytes, iterations)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt_padded = cipher.decrypt(ct)
    plaintext = unpad(pt_padded, AES.block_size)
    data = json.loads(plaintext.decode("utf-8"))
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

class App:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("680x380")
        self.root.minsize(660, 360)

        self.mode = StringVar(value="encrypt")
        self.input_path = StringVar(value="")
        self.output_path = StringVar(value="")
        self.password = StringVar(value="")
        self.password2 = StringVar(value="")
        self.iterations = StringVar(value=str(DEFAULT_ITER))
        self.aes256 = BooleanVar(value=True)
        self.busy = False

        self._build_ui()

    def _build_ui(self):
        pad = {"padx": 10, "pady": 8}
        frm = ttk.Frame(self.root)
        frm.pack(fill="both", expand=True, **pad)

        # Mode
        row1 = ttk.Frame(frm); row1.pack(fill="x", **pad)
        ttk.Label(row1, text="Mode:").pack(side="left")
        ttk.Radiobutton(row1, text="Encrypt JSON → BIN", variable=self.mode, value="encrypt", command=self._on_mode_change).pack(side="left", padx=10)
        ttk.Radiobutton(row1, text="Decrypt BIN → JSON", variable=self.mode, value="decrypt", command=self._on_mode_change).pack(side="left", padx=10)

        # Input
        row2 = ttk.Frame(frm); row2.pack(fill="x", **pad)
        ttk.Label(row2, text="Input file:").pack(side="left")
        self.in_entry = ttk.Entry(row2, textvariable=self.input_path)
        self.in_entry.pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(row2, text="Browse…", command=self._browse_input).pack(side="left")
        if DNDSUPPORTED:
            self.in_entry.drop_target_register(DND_FILES)
            self.in_entry.dnd_bind("<<Drop>>", self._on_drop_input)

        # Output
        row3 = ttk.Frame(frm); row3.pack(fill="x", **pad)
        ttk.Label(row3, text="Output file:").pack(side="left")
        self.out_entry = ttk.Entry(row3, textvariable=self.output_path)
        self.out_entry.pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(row3, text="Browse…", command=self._browse_output).pack(side="left")
        if DNDSUPPORTED:
            self.out_entry.drop_target_register(DND_FILES)
            self.out_entry.dnd_bind("<<Drop>>", self._on_drop_output)

        # Password
        row4 = ttk.Frame(frm); row4.pack(fill="x", **pad)
        ttk.Label(row4, text="Password:").pack(side="left")
        self.pw_entry = ttk.Entry(row4, textvariable=self.password, show="•")
        self.pw_entry.pack(side="left", fill="x", expand=True, padx=8)

        # Confirm
        self.row_confirm = ttk.Frame(frm); self.row_confirm.pack(fill="x", **pad)
        ttk.Label(self.row_confirm, text="Confirm:").pack(side="left")
        self.pw2_entry = ttk.Entry(self.row_confirm, textvariable=self.password2, show="•")
        self.pw2_entry.pack(side="left", fill="x", expand=True, padx=8)

        # Options
        row5 = ttk.Frame(frm); row5.pack(fill="x", **pad)
        ttk.Checkbutton(row5, text="AES-256 (khuyến nghị)", variable=self.aes256).pack(side="left")
        ttk.Label(row5, text="PBKDF2 rounds:").pack(side="left", padx=(16, 6))
        self.iter_entry = ttk.Entry(row5, textvariable=self.iterations, width=12)
        self.iter_entry.pack(side="left")

        # ✅ dùng tk.Label để set màu
        if DNDSUPPORTED:
            tk.Label(row5, text=" (Drag-and-drop: ON)", fg="#0a0").pack(side="left", padx=8)
        else:
            tk.Label(row5, text=" (Drag-and-drop: OFF — cài 'tkinterdnd2')", fg="#a60").pack(side="left", padx=8)

        # Progress + Run
        row6 = ttk.Frame(frm); row6.pack(fill="x", **pad)
        self.progress = ttk.Progressbar(row6, mode="indeterminate")
        self.progress.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.btn_run = ttk.Button(row6, text="RUN", command=self._run_clicked)
        self.btn_run.pack(side="left")

        self._on_mode_change()

    # Drag & Drop helpers
    @staticmethod
    def _clean_dnd_path(dnd_event_data: str) -> str:
        if not dnd_event_data:
            return ""
        s = dnd_event_data.strip()
        if " " in s and s.startswith("{") and s.endswith("}"):
            s = s[1:-1]
        if " } {" in dnd_event_data:
            s = dnd_event_data.split("} {")[0].strip("{}")
        return s.strip('"')

    def _on_drop_input(self, event):
        p = self._clean_dnd_path(event.data)
        if p:
            self.input_path.set(p)
            self._suggest_output()

    def _on_drop_output(self, event):
        p = self._clean_dnd_path(event.data)
        if p:
            self.output_path.set(p)

    def _on_mode_change(self):
        if self.mode.get() == "encrypt":
            self.row_confirm.pack_configure(fill="x")
        else:
            self.row_confirm.pack_forget()
        if self.input_path.get():
            self._suggest_output()

    def _browse_input(self):
        mode = self.mode.get()
        if mode == "encrypt":
            fp = filedialog.askopenfilename(title="Chọn JSON", filetypes=[("JSON", "*.json")])
        else:
            fp = filedialog.askopenfilename(title="Chọn BIN", filetypes=[("BIN", "*.bin")])
        if fp:
            self.input_path.set(fp)
            self._suggest_output()

    def _browse_output(self):
        mode = self.mode.get()
        if mode == "encrypt":
            fp = filedialog.asksaveasfilename(defaultextension=".bin")
        else:
            fp = filedialog.asksaveasfilename(defaultextension=".json")
        if fp:
            self.output_path.set(fp)

    def _suggest_output(self):
        try:
            ip = Path(self.input_path.get())
            if not ip.name:
                return
            if self.mode.get() == "encrypt":
                suggested = ip.with_suffix(ip.suffix + ".enc.bin")
            else:
                suggested = ip.with_suffix(".json")
            self.output_path.set(str(suggested))
        except Exception:
            pass

    def _run_clicked(self):
        if self.busy:
            return
        try:
            mode = self.mode.get()
            ip, op = self.input_path.get().strip(), self.output_path.get().strip()
            pw, pw2 = self.password.get(), self.password2.get()
            iters = int(self.iterations.get())
            key_len = 32 if self.aes256.get() else 16
            if not ip or not op:
                messagebox.showerror("Lỗi", "Chưa chọn file.")
                return
            if mode == "encrypt" and pw != pw2:
                messagebox.showerror("Lỗi", "Mật khẩu nhập lại không khớp.")
                return
            in_path, out_path = Path(ip), Path(op)
            self._set_busy(True)
            t = threading.Thread(target=self._do_work, args=(mode, in_path, out_path, pw, key_len, iters), daemon=True)
            t.start()
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))

    def _do_work(self, mode, in_path, out_path, pw, key_len, iters):
        try:
            if mode == "encrypt":
                encrypt_json_file(in_path, out_path, pw, key_len, iters)
            else:
                decrypt_blob_to_json(in_path, out_path, pw, key_len, iters)
        except Exception as e:
            self._done(False, str(e))
            return
        self._done(True, "Hoàn tất ✅")

    def _set_busy(self, flag: bool):
        self.busy = flag
        if flag:
            self.progress.start(10)
            self.btn_run.configure(state="disabled", text="Running…")
        else:
            self.progress.stop()
            self.btn_run.configure(state="normal", text="RUN")

    def _done(self, ok: bool, msg: str):
        def _ui():
            self._set_busy(False)
            if ok:
                messagebox.showinfo("Done", msg)
            else:
                messagebox.showerror("Lỗi", msg)
        self.root.after(0, _ui)

def main():
    root = TkinterDnD.Tk() if DNDSUPPORTED else Tk()
    App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
