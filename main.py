import sqlite3
import os
import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.fernet import Fernet

DB_FILE = "api_keys.db"
KEY_FILE = "secret.key"

# QUY TẮC TỰ NHẬN DIỆN MODEL
# tiền tố của API key, nhà cung cấp, model mặc định
# Lưu ý: các tiền tố dài hơn phải đặt trước, ví dụ "sk-ant-" trước "sk-"
AUTO_MODEL_RULES = [
    ("sk-ant-", "Anthropic", "claude-sonnet-4-5"),
    ("sk-or-", "OpenRouter", "auto"),
    ("sk-proj-", "OpenAI", "gpt-4o"),
    ("sk-", "OpenAI", "gpt-4o"),
    ("AIza", "Google", "gemini-2.5-pro"),
    ("gsk_", "Groq, Inc", "openai/gpt-oss-120b"),
    ("xai-", "xAI", "grok-4"),
    ("hf_", "HuggingFace", "meta-llama/Llama-3.1-8B-Instruct"),
]

# Bảng màu và font 
BG = "#0f1117"
PANEL = "#171a23"
CARD = "#1e2230"
ACCENT = "#6c8cff"
ACCENT_HOVER = "#8aa3ff"
TEXT = "#e6e8ef"
MUTED = "#8b91a7"
DANGER = "#ff5c6c"
SUCCESS = "#3ddc97"
BORDER = "#2a2f3f"
FONT = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_TITLE = ("Segoe UI", 16, "bold")


def load_or_create_secret():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key


def detect_provider_model(api_key):
    """Trả về (provider, model) theo quy tắc AUTO_MODEL_RULES, hoặc None nếu không nhận ra."""
    for prefix, provider, model in AUTO_MODEL_RULES:
        if api_key.startswith(prefix):
            return provider, model
    return None


class Storage:
    def __init__(self):
        self.fernet = Fernet(load_or_create_secret())
        self.conn = sqlite3.connect(DB_FILE)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                encrypted_key TEXT NOT NULL,
                note TEXT
            )
        """)
        self.conn.commit()

    def unique_name(self, base, exclude_id=None):
        """Nếu tên đã có thì thêm số: 'Tên', 'Tên 2', 'Tên 3'..."""
        rows = self.conn.execute("SELECT id, name FROM api_keys").fetchall()
        taken = {name for id_, name in rows if id_ != exclude_id}
        if base not in taken:
            return base
        n = 2
        while f"{base} {n}" in taken:
            n += 1
        return f"{base} {n}"

    def add(self, name, provider, model, key, note):
        name = self.unique_name(name)
        enc = self.fernet.encrypt(key.encode()).decode()
        self.conn.execute(
            "INSERT INTO api_keys (name, provider, model, encrypted_key, note) VALUES (?,?,?,?,?)",
            (name, provider, model, enc, note))
        self.conn.commit()
        return name

    def update(self, id_, name, provider, model, key, note):
        name = self.unique_name(name, exclude_id=id_)
        enc = self.fernet.encrypt(key.encode()).decode()
        self.conn.execute(
            "UPDATE api_keys SET name=?, provider=?, model=?, encrypted_key=?, note=? WHERE id=?",
            (name, provider, model, enc, note, id_))
        self.conn.commit()
        return name

    def delete(self, id_):
        self.conn.execute("DELETE FROM api_keys WHERE id=?", (id_,))
        self.conn.commit()

    def get(self, id_):
        row = self.conn.execute(
            "SELECT id, name, provider, model, encrypted_key, note FROM api_keys WHERE id=?",
            (id_,)).fetchone()
        if not row:
            return None
        id_, name, prov, mdl, enc, note = row
        return {"id": id_, "name": name, "provider": prov, "model": mdl,
                "key": self.fernet.decrypt(enc.encode()).decode(), "note": note}

    def list(self, provider=None, search=""):
        q = "SELECT id, name, provider, model, encrypted_key, note FROM api_keys WHERE 1=1"
        p = []
        if provider:
            q += " AND provider=?"
            p.append(provider)
        if search:
            q += " AND (name LIKE ? OR model LIKE ? OR note LIKE ?)"
            p += [f"%{search}%"] * 3
        q += " ORDER BY provider, model, name"
        out = []
        for id_, name, prov, mdl, enc, note in self.conn.execute(q, p).fetchall():
            raw = self.fernet.decrypt(enc.encode()).decode()
            masked = raw[:4] + "•" * 8 + raw[-4:] if len(raw) > 8 else "••••••••"
            out.append({"id": id_, "name": name, "provider": prov, "model": mdl,
                        "masked": masked, "note": note or ""})
        return out

    def providers(self):
        return self.conn.execute(
            "SELECT provider, COUNT(*) FROM api_keys GROUP BY provider ORDER BY provider").fetchall()

    def total(self):
        return self.conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0]


def make_button(parent, text, command, secondary=False, danger=False):
    if danger:
        bg, hover = DANGER, "#ff7a86"
    elif secondary:
        bg, hover = CARD, BORDER
    else:
        bg, hover = ACCENT, ACCENT_HOVER
    btn = tk.Label(parent, text=text, bg=bg, fg="white" if not secondary else TEXT,
                   font=FONT_BOLD, padx=16, pady=7, cursor="hand2")
    btn.bind("<Button-1>", lambda e: command())
    btn.bind("<Enter>", lambda e: btn.config(bg=hover))
    btn.bind("<Leave>", lambda e: btn.config(bg=bg))
    return btn


class KeyDialog(tk.Toplevel):
    """Hộp thoại thêm / sửa key, có tự nhận diện model khi nhập key."""
    def __init__(self, parent, storage, data=None, on_done=None):
        super().__init__(parent)
        self.storage = storage
        self.data = data
        self.on_done = on_done
        self.title("Sửa API key" if data else "Thêm API key")
        self.configure(bg=PANEL)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        frm = tk.Frame(self, bg=PANEL, padx=24, pady=20)
        frm.pack(fill="both", expand=True)

        tk.Label(frm, text=self.title(), bg=PANEL, fg=TEXT, font=FONT_TITLE).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 16))

        self.fields = {}
        labels = [("name", "Tên gợi nhớ"), ("key", "API key"), ("provider", "Nhà cung cấp"),
                  ("model", "Model"), ("note", "Ghi chú")]
        for i, (k, label) in enumerate(labels, start=1):
            tk.Label(frm, text=label, bg=PANEL, fg=MUTED, font=FONT).grid(
                row=i, column=0, sticky="w", pady=6, padx=(0, 12))
            entry = tk.Entry(frm, width=40, bg=CARD, fg=TEXT, insertbackground=TEXT,
                             relief="flat", font=FONT, highlightthickness=1,
                             highlightbackground=BORDER, highlightcolor=ACCENT,
                             show="•" if k == "key" else "")
            entry.grid(row=i, column=1, sticky="ew", ipady=6)
            self.fields[k] = entry

        if data:
            for k in ("name", "provider", "model", "key", "note"):
                self.fields[k].insert(0, data.get(k, "") or "")

        # Dòng gợi ý tự nhận diện
        self.hint = tk.Label(frm, text="", bg=PANEL, fg=SUCCESS, font=("Segoe UI", 9))
        self.hint.grid(row=len(labels) + 1, column=1, sticky="w")
        self.fields["key"].bind("<KeyRelease>", lambda e: self.auto_detect())

        btns = tk.Frame(frm, bg=PANEL)
        btns.grid(row=len(labels) + 2, column=0, columnspan=2, sticky="e", pady=(20, 0))
        make_button(btns, "Hủy", self.destroy, secondary=True).pack(side="left", padx=6)
        make_button(btns, "Lưu", self.save).pack(side="left")

        self.fields["name"].focus_set()
        self.bind("<Return>", lambda e: self.save())
        self.bind("<Escape>", lambda e: self.destroy())

    def auto_detect(self):
        """Khi đang nhập key: tự điền provider/model nếu đang trống."""
        key = self.fields["key"].get().strip()
        result = detect_provider_model(key)
        if not result:
            self.hint.config(text="")
            return
        provider, model = result
        self.hint.config(text=f"Nhận diện: {provider} / {model}")
        if not self.fields["provider"].get().strip():
            self.fields["provider"].insert(0, provider)
        if not self.fields["model"].get().strip():
            self.fields["model"].insert(0, model)

    def save(self):
        v = {k: e.get().strip() for k, e in self.fields.items()}
        if not v["key"]:
            messagebox.showwarning("Thiếu thông tin", "Vui lòng nhập API key.", parent=self)
            return

        # Tự nhận diện nếu provider/model còn trống
        if not (v["provider"] and v["model"]):
            result = detect_provider_model(v["key"])
            if result:
                v["provider"] = v["provider"] or result[0]
                v["model"] = v["model"] or result[1]
            else:
                messagebox.showwarning(
                    "Không nhận diện được",
                    "Không nhận ra loại key. Vui lòng nhập nhà cung cấp và model.", parent=self)
                return

        # Tên trống thì tự đặt theo provider + model
        if not v["name"]:
            v["name"] = f"{v['provider']} {v['model']}"

        if self.data:
            self.storage.update(self.data["id"], v["name"], v["provider"],
                                v["model"], v["key"], v["note"])
        else:
            self.storage.add(v["name"], v["provider"], v["model"], v["key"], v["note"])

        if self.on_done:
            self.on_done()
        self.destroy()


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.storage = Storage()
        self.title("API Key Manager")
        self.geometry("1100x650")
        self.minsize(900, 550)
        self.configure(bg=BG)
        self.selected_provider = None
        self.show_plain = False
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self.refresh())
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        # ----- Sidebar -----
        side = tk.Frame(self, bg=PANEL, width=240)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)

        tk.Label(side, text="🔐 API Keys", bg=PANEL, fg=TEXT, font=FONT_TITLE).pack(
            anchor="w", padx=20, pady=(24, 4))
        tk.Label(side, text="Phân loại theo nhà cung cấp", bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 9)).pack(anchor="w", padx=20, pady=(0, 18))

        self.provider_list = tk.Frame(side, bg=PANEL)
        self.provider_list.pack(fill="x", padx=12)

        # ----- Main -----
        main = tk.Frame(self, bg=BG)
        main.pack(side="left", fill="both", expand=True)

        header = tk.Frame(main, bg=BG)
        header.pack(fill="x", padx=28, pady=(24, 12))
        self.title_lbl = tk.Label(header, text="Tất cả key", bg=BG, fg=TEXT,
                                  font=("Segoe UI", 18, "bold"))
        self.title_lbl.pack(side="left")
        make_button(header, "+ Thêm key", self.add_key).pack(side="right")

        toolbar = tk.Frame(main, bg=BG)
        toolbar.pack(fill="x", padx=28, pady=(0, 14))
        search = tk.Entry(toolbar, textvariable=self.search_var, bg=CARD, fg=TEXT,
                          insertbackground=TEXT, relief="flat", font=FONT,
                          highlightthickness=1, highlightbackground=BORDER,
                          highlightcolor=ACCENT)
        search.pack(side="left", fill="x", expand=True, ipady=7)
        tk.Label(toolbar, text="  🔍 Tìm theo tên / model / ghi chú", bg=BG, fg=MUTED,
                 font=("Segoe UI", 9)).pack(side="left", padx=8)

        # ----- Table -----
        table_wrap = tk.Frame(main, bg=BG)
        table_wrap.pack(fill="both", expand=True, padx=28)

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Dark.Treeview", background=CARD, fieldbackground=CARD,
                        foreground=TEXT, rowheight=36, bordercolor=BG, font=FONT)
        style.configure("Dark.Treeview.Heading", background=PANEL, foreground=MUTED,
                        font=FONT_BOLD, relief="flat", padding=8)
        style.map("Dark.Treeview", background=[("selected", ACCENT)],
                  foreground=[("selected", "white")])
        style.map("Dark.Treeview.Heading", background=[("active", BORDER)])

        cols = ("provider", "model", "name", "key", "note")
        self.tree = ttk.Treeview(table_wrap, columns=cols, show="headings",
                                 style="Dark.Treeview", selectmode="browse")
        widths = {"provider": 130, "model": 170, "name": 180, "key": 200, "note": 260}
        heads = {"provider": "Nhà cung cấp", "model": "Model", "name": "Tên",
                 "key": "API key", "note": "Ghi chú"}
        for c in cols:
            self.tree.heading(c, text=heads[c], anchor="w")
            self.tree.column(c, width=widths[c], anchor="w")

        scroll = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", lambda e: self.edit_key())

        # ----- Action bar -----
        bar = tk.Frame(main, bg=BG)
        bar.pack(fill="x", padx=28, pady=18)
        self.count_lbl = tk.Label(bar, text="", bg=BG, fg=MUTED, font=FONT)
        self.count_lbl.pack(side="left")
        make_button(bar, "Xóa", self.delete_key, danger=True).pack(side="right", padx=6)
        make_button(bar, "Sửa", self.edit_key, secondary=True).pack(side="right", padx=6)
        make_button(bar, "Sao chép key", self.copy_key, secondary=True).pack(side="right", padx=6)
        make_button(bar, "Hiện / ẩn", self.toggle_show, secondary=True).pack(side="right", padx=6)

    # ----- Logic -----
    def refresh(self):
        for w in self.provider_list.winfo_children():
            w.destroy()

        self._sidebar_item("Tất cả", None, self.storage.total())
        for prov, cnt in self.storage.providers():
            self._sidebar_item(prov, prov, cnt)

        self.tree.delete(*self.tree.get_children())
        rows = self.storage.list(self.selected_provider, self.search_var.get().strip())
        for r in rows:
            key_display = self._display_key(r["id"], r["masked"])
            self.tree.insert("", "end", iid=str(r["id"]),
                             values=(r["provider"], r["model"], r["name"], key_display, r["note"]))
        self.count_lbl.config(text=f"{len(rows)} key")
        self.title_lbl.config(text=self.selected_provider or "Tất cả key")

    def _sidebar_item(self, text, provider, count):
        active = provider == self.selected_provider
        bg = ACCENT if active else PANEL
        row = tk.Frame(self.provider_list, bg=bg, cursor="hand2")
        row.pack(fill="x", pady=2)
        lbl1 = tk.Label(row, text=text, bg=bg, fg="white" if active else TEXT,
                        font=FONT_BOLD, anchor="w", padx=12, pady=8)
        lbl1.pack(side="left", fill="x", expand=True)
        lbl2 = tk.Label(row, text=str(count), bg=bg, fg="white" if active else MUTED,
                        font=FONT, padx=12)
        lbl2.pack(side="right")
        for w in (row, lbl1, lbl2):
            w.bind("<Button-1>", lambda e, p=provider: self.select_provider(p))
            if not active:
                w.bind("<Enter>", lambda e, r=row: r.config(bg=CARD))
                w.bind("<Leave>", lambda e, r=row: r.config(bg=PANEL))

    def _display_key(self, id_, masked):
        if self.show_plain:
            return self.storage.get(id_)["key"]
        return masked

    def select_provider(self, provider):
        self.selected_provider = provider
        self.refresh()

    def toggle_show(self):
        self.show_plain = not self.show_plain
        self.refresh()

    def _selected_id(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Chưa chọn", "Vui lòng chọn một key trong danh sách.")
            return None
        return int(sel[0])

    def add_key(self):
        KeyDialog(self, self.storage, on_done=self.refresh)

    def edit_key(self):
        id_ = self._selected_id()
        if id_ is None:
            return
        KeyDialog(self, self.storage, data=self.storage.get(id_), on_done=self.refresh)

    def delete_key(self):
        id_ = self._selected_id()
        if id_ is None:
            return
        if messagebox.askyesno("Xác nhận", "Bạn có chắc muốn xóa key này?"):
            self.storage.delete(id_)
            self.refresh()

    def copy_key(self):
        id_ = self._selected_id()
        if id_ is None:
            return
        self.clipboard_clear()
        self.clipboard_append(self.storage.get(id_)["key"])
        messagebox.showinfo("Đã sao chép", "API key đã được sao chép vào clipboard.")


if __name__ == "__main__":
    App().mainloop()