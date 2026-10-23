

import hashlib
import hmac
import json
import math
import os
import secrets
import shutil
import string
import time
import uuid
from datetime import datetime
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    from PIL import Image, ImageOps, ImageTk
    PIL_OK = True
except ImportError:  # Pillow is optional
    PIL_OK = False


# =========================
# CONSTANTS
# =========================

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("PETLINK_DATA_DIR") or (APP_DIR / "petlink_data"))
DB_FILE = DATA_DIR / "petlink_data.json"
PHOTO_DIR = DATA_DIR / "photos"

PASSWORD_MIN = 8
PASSWORD_MAX = 13
PBKDF2_ITERATIONS = 150_000

ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "Admin@1234"

MAX_PHOTO_BYTES = 8 * 1024 * 1024
PHOTO_EXTENSIONS = (
    (".png", ".gif", ".jpg", ".jpeg", ".bmp", ".webp") if PIL_OK
    else (".png", ".gif")
)

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 60

STRAY_STATUSES = ["Pending", "In Progress", "Rescued", "Closed"]
STRAY_TRANSITIONS = {
    "Pending": ["In Progress", "Closed"],
    "In Progress": ["Rescued", "Closed"],
    "Rescued": ["Closed"],
    "Closed": ["Pending"],  # reopen (administrator only)
}


# =========================
# SECURITY HELPERS
# =========================

def hash_password(password, iterations=PBKDF2_ITERATIONS):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password, stored):
    try:
        algo, iterations, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"),
            bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(digest.hex(), hash_hex)
    except (ValueError, AttributeError, TypeError):
        return False


DUMMY_HASH = hash_password("dummy-password")


def validate_password(password):
    """Return an error message, or None if the password is acceptable."""
    if len(password) < PASSWORD_MIN:
        return f"Password must be at least {PASSWORD_MIN} characters long."
    if len(password) > PASSWORD_MAX:
        return f"Password must be no more than {PASSWORD_MAX} characters long."
    return None


def valid_name(text):
    text = text.strip()
    if not text or len(text) > 30:
        return False
    if not any(ch.isalpha() for ch in text):
        return False
    return all(ch.isalpha() or ch in " -'." for ch in text)


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def fmt_dt(iso_text):
    try:
        return datetime.fromisoformat(iso_text).strftime("%b %d, %Y %I:%M %p")
    except (TypeError, ValueError):
        return iso_text or ""


def format_age(years):
    if years == 0:
        return "Less than 1 year"
    return "1 year" if years == 1 else f"{years} years"


# =========================
# PHOTO STORAGE
# =========================

def store_photo(source_path):
    """Validate and copy a photo into PHOTO_DIR. Returns (filename, error)."""
    source = Path(source_path)
    if not source.is_file():
        return None, "The selected photo could not be found."
    if source.stat().st_size > MAX_PHOTO_BYTES:
        return None, "The photo is too large (maximum 8 MB)."
    ext = source.suffix.lower()
    if ext not in PHOTO_EXTENSIONS:
        allowed = ", ".join(PHOTO_EXTENSIONS)
        return None, f"Unsupported photo type. Allowed types: {allowed}"

    PHOTO_DIR.mkdir(parents=True, exist_ok=True)
    name = uuid.uuid4().hex
    try:
        if PIL_OK:
            dest = PHOTO_DIR / f"{name}.jpg"
            with Image.open(source) as img:
                img = ImageOps.exif_transpose(img)
                if img.mode in ("RGBA", "LA", "P"):
                    img = img.convert("RGBA")
                    background = Image.new("RGB", img.size, "white")
                    background.paste(img, mask=img.split()[-1])
                    img = background
                else:
                    img = img.convert("RGB")
                img.thumbnail((900, 900))
                img.save(dest, "JPEG", quality=88)
        else:
            dest = PHOTO_DIR / f"{name}{ext}"
            shutil.copy2(source, dest)
            tk.PhotoImage(file=str(dest))  # raises TclError if invalid
    except Exception:
        try:
            dest.unlink()
        except (OSError, UnboundLocalError):
            pass
        return None, "The selected file is not a valid image."
    return dest.name, None


def delete_photo_file(filename):
    if not filename:
        return
    try:
        (PHOTO_DIR / Path(filename).name).unlink()
    except OSError:
        pass


# =========================
# DATABASE (JSON)
# =========================

class Database:
    """JSON-backed storage plus all business rules."""

    def __init__(self, path=None):
        self.path = Path(path or DB_FILE)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        PHOTO_DIR.mkdir(parents=True, exist_ok=True)
        self.data = self._load()
        self._repair()
        self._ensure_admin()
        self.save()

    # ---------- persistence ----------

    @staticmethod
    def _empty():
        return {
            "version": 1,
            "counters": {"pet": 0, "application": 0, "report": 0},
            "accounts": {},
            "pets": [],
            "applications": [],
            "stray_reports": [],
        }

    @staticmethod
    def _read_json(path):
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            raise ValueError("Invalid database structure")
        return data

    def _load(self):
        data = None
        if self.path.exists():
            try:
                data = self._read_json(self.path)
            except (OSError, ValueError):
                stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                try:
                    shutil.copy2(
                        self.path,
                        self.path.with_name(f"{self.path.name}.corrupt-{stamp}")
                    )
                except OSError:
                    pass
                backup = self.path.with_name(self.path.name + ".bak")
                if backup.exists():
                    try:
                        data = self._read_json(backup)
                    except (OSError, ValueError):
                        data = None
        if data is None:
            data = self._empty()
        for key, value in self._empty().items():
            data.setdefault(key, value)
        if not isinstance(data["counters"], dict):
            data["counters"] = self._empty()["counters"]
        for key in ("pet", "application", "report"):
            data["counters"].setdefault(key, 0)
        return data

    def _repair(self):
        d = self.data
        if not isinstance(d["accounts"], dict):
            d["accounts"] = {}
        d["accounts"] = {
            name: acc for name, acc in d["accounts"].items()
            if isinstance(acc, dict) and "password" in acc
        }
        for key in ("pets", "applications", "stray_reports"):
            if not isinstance(d[key], list):
                d[key] = []
            d[key] = [
                r for r in d[key]
                if isinstance(r, dict) and isinstance(r.get("id"), int)
            ]
        pet_ids = {p["id"] for p in d["pets"]}
        d["applications"] = [
            a for a in d["applications"] if a.get("pet_id") in pet_ids
        ]
        for pet in d["pets"]:
            pet.setdefault("status", "Available")
            pet.setdefault("photo", "")
            pet.setdefault("info", "")
        for report in d["stray_reports"]:
            if report.get("status") not in STRAY_STATUSES:
                report["status"] = "Pending"
            report.setdefault("history", [])
            report.setdefault("photo", "")
        for kind, key in (("pet", "pets"), ("application", "applications"),
                          ("report", "stray_reports")):
            highest = max((r["id"] for r in d[key]), default=0)
            d["counters"][kind] = max(d["counters"].get(kind, 0), highest)

    def _ensure_admin(self):
        acc = self.accounts.get(ADMIN_USERNAME)
        if acc is None or acc.get("role") != "admin":
            self.accounts[ADMIN_USERNAME] = {
                "password": hash_password(DEFAULT_ADMIN_PASSWORD),
                "first_name": "System",
                "last_name": "Administrator",
                "role": "admin",
                "created_at": now_iso(),
                "must_change_password": True,
            }

    def save(self):
        tmp = self.path.with_name(self.path.name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(self.data, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        if self.path.exists():
            try:
                shutil.copy2(self.path, self.path.with_name(self.path.name + ".bak"))
            except OSError:
                pass
        os.replace(tmp, self.path)

    # ---------- accessors ----------

    @property
    def accounts(self):
        return self.data["accounts"]

    @property
    def pets(self):
        return self.data["pets"]

    @property
    def applications(self):
        return self.data["applications"]

    @property
    def stray_reports(self):
        return self.data["stray_reports"]

    def next_id(self, kind):
        self.data["counters"][kind] += 1
        return self.data["counters"][kind]

    def get_pet(self, pet_id):
        return next((p for p in self.pets if p["id"] == pet_id), None)

    def get_application(self, app_id):
        return next((a for a in self.applications if a["id"] == app_id), None)

    def get_report(self, report_id):
        return next((r for r in self.stray_reports if r["id"] == report_id), None)

    def full_name(self, username):
        acc = self.accounts.get(username)
        if not acc:
            return f"{username} (deleted)"
        return f"{acc['first_name']} {acc['last_name']}"

    def is_admin(self, username):
        acc = self.accounts.get(username)
        return bool(acc and acc.get("role") == "admin")

    # ---------- accounts ----------

    def create_account(self, first, last, password):
        base = "".join(c.lower() for c in first + last if c.isalpha()) or "user"
        username, counter = base, 1
        while username in self.accounts or username == ADMIN_USERNAME:
            counter += 1
            username = f"{base}{counter}"
        self.accounts[username] = {
            "password": hash_password(password),
            "first_name": first,
            "last_name": last,
            "role": "user",
            "created_at": now_iso(),
            "must_change_password": False,
        }
        self.save()
        return username

    def set_password(self, username, password, must_change=False):
        acc = self.accounts[username]
        acc["password"] = hash_password(password)
        acc["must_change_password"] = must_change
        self.save()

    def delete_user(self, username):
        if username not in self.accounts:
            return False, "User not found."
        if self.is_admin(username):
            return False, "The administrator account cannot be deleted."
        # Applications made by this user (relist pets they had been approved for)
        for app in [a for a in self.applications if a["username"] == username]:
            self._remove_application(app)
        # Pets posted by this user
        for pet in [p for p in self.pets if p["posted_by"] == username]:
            self._remove_pet(pet)
        # Stray reports
        for report in [r for r in self.stray_reports if r["reported_by"] == username]:
            delete_photo_file(report.get("photo"))
            self.stray_reports.remove(report)
        del self.accounts[username]
        self.save()
        return True, "User deleted."

    # ---------- pets ----------

    def add_pet(self, name, age, breed, animal_type, info, photo, posted_by):
        pet = {
            "id": self.next_id("pet"),
            "name": name,
            "age": age,
            "breed": breed,
            "animal_type": animal_type,
            "info": info,
            "photo": photo or "",
            "category": "Pet for Adoption",
            "status": "Available",
            "posted_by": posted_by,
            "created_at": now_iso(),
        }
        self.pets.append(pet)
        self.save()
        return pet

    def _remove_pet(self, pet):
        for app in [a for a in self.applications if a["pet_id"] == pet["id"]]:
            self.applications.remove(app)
        delete_photo_file(pet.get("photo"))
        if pet in self.pets:
            self.pets.remove(pet)

    def delete_pet(self, pet_id):
        pet = self.get_pet(pet_id)
        if not pet:
            return False, "Pet not found."
        self._remove_pet(pet)
        self.save()
        return True, "Pet listing removed."

    # ---------- applications ----------

    def apply_to_pet(self, username, pet_id):
        pet = self.get_pet(pet_id)
        if not pet:
            return False, "This pet no longer exists."
        if self.is_admin(username):
            return False, "Administrators cannot adopt pets."
        if pet["posted_by"] == username:
            return False, "You cannot adopt a pet that you posted yourself."
        if pet["status"] != "Available":
            return False, "This pet is no longer available for adoption."
        if any(a["pet_id"] == pet_id and a["username"] == username
               and a["status"] == "Pending" for a in self.applications):
            return False, "You already have a pending application for this pet."
        self.applications.append({
            "id": self.next_id("application"),
            "pet_id": pet_id,
            "username": username,
            "status": "Pending",
            "created_at": now_iso(),
            "updated_at": now_iso(),
            "decided_by": "",
        })
        self.save()
        return True, "Application submitted."

    def cancel_application(self, app_id, username):
        app = self.get_application(app_id)
        if not app or app["username"] != username:
            return False, "Application not found."
        if app["status"] != "Pending":
            return False, "Only pending applications can be cancelled."
        app["status"] = "Cancelled"
        app["updated_at"] = now_iso()
        self.save()
        return True, "Application cancelled."

    def decide_application(self, app_id, decision, by):
        if decision not in ("Approved", "Rejected"):
            return False, "Invalid decision."
        app = self.get_application(app_id)
        if not app:
            return False, "Application not found."
        pet = self.get_pet(app["pet_id"])
        if not pet:
            return False, "The pet for this application no longer exists."
        if not (self.is_admin(by) or pet["posted_by"] == by):
            return False, "You are not allowed to decide this application."
        if app["status"] != "Pending":
            return False, f"This application is already {app['status']}."
        if decision == "Approved":
            if app["username"] == pet["posted_by"]:
                return False, "A pet cannot be adopted by its own poster."
            if pet["status"] != "Available":
                return False, "This pet is no longer available."
            pet["status"] = "Adopted"
            pet["adopted_by"] = app["username"]
            for other in self.applications:
                if (other is not app and other["pet_id"] == pet["id"]
                        and other["status"] == "Pending"):
                    other["status"] = "Rejected"
                    other["updated_at"] = now_iso()
                    other["decided_by"] = by
        app["status"] = decision
        app["updated_at"] = now_iso()
        app["decided_by"] = by
        self.save()
        return True, f"Application {decision.lower()}."

    def _remove_application(self, app):
        pet = self.get_pet(app["pet_id"])
        if (app["status"] == "Approved" and pet
                and pet.get("adopted_by") == app["username"]):
            pet["status"] = "Available"
            pet.pop("adopted_by", None)
        if app in self.applications:
            self.applications.remove(app)

    def delete_application(self, app_id):
        app = self.get_application(app_id)
        if not app:
            return False, "Application not found."
        self._remove_application(app)
        self.save()
        return True, "Application record deleted."

    # ---------- stray reports ----------

    def add_report(self, name, age, breed, animal_type, location, info,
                   photo, reported_by):
        report = {
            "id": self.next_id("report"),
            "name": name,
            "age": age,
            "breed": breed,
            "type": animal_type,
            "location": location,
            "province": "Pangasinan",
            "info": info,
            "photo": photo or "",
            "status": "Pending",
            "reported_by": reported_by,
            "created_at": now_iso(),
            "updated_at": now_iso(),
            "history": [{
                "status": "Pending", "by": reported_by,
                "at": now_iso(), "note": "Report submitted",
            }],
        }
        self.stray_reports.append(report)
        self.save()
        return report

    def allowed_report_statuses(self, report, username):
        options = list(STRAY_TRANSITIONS.get(report["status"], []))
        if self.is_admin(username):
            return options
        if report["reported_by"] == username:
            return [s for s in options if s == "Closed"]
        return []

    def set_report_status(self, report_id, new_status, by):
        report = self.get_report(report_id)
        if not report:
            return False, "Report not found."
        if new_status not in STRAY_STATUSES:
            return False, "Invalid status."
        if report["status"] == new_status:
            return False, f"This report is already {new_status}."
        if new_status not in self.allowed_report_statuses(report, by):
            return False, (
                f"A report that is {report['status']} cannot be changed to "
                f"{new_status} by you."
            )
        report["status"] = new_status
        report["updated_at"] = now_iso()
        report["history"].append({
            "status": new_status, "by": by, "at": now_iso(),
            "note": "Status updated",
        })
        self.save()
        return True, f"Status changed to {new_status}."

    def delete_report(self, report_id):
        report = self.get_report(report_id)
        if not report:
            return False, "Report not found."
        delete_photo_file(report.get("photo"))
        self.stray_reports.remove(report)
        self.save()
        return True, "Stray report deleted."


# =========================
# APPLICATION (GUI)
# =========================

class PetLink:
    def __init__(self, root):
        self.root = root
        self.root.title("PetLink: An Online Adoption & Tracking System")
        self.root.geometry("1000x650")
        self.root.minsize(760, 560)

        # COLORS
        self.BG_COLOR = "#EAF4F4"
        self.NAV_COLOR = "#315B5B"
        self.BUTTON_COLOR = "#568585"
        self.WHITE = "#FFFFFF"
        self.TEXT_COLOR = "#222222"
        self.SUBTEXT_COLOR = "#777777"
        self.GREEN = "#4F8A5B"
        self.RED = "#B85C5C"
        self.YELLOW = "#B58B35"
        self.LIGHT_YELLOW = "#FFF3D6"
        self.BLUE = "#2F6F9F"

        # (text colour, background colour) for status badges
        self.STATUS_STYLES = {
            "Pending": (self.YELLOW, self.LIGHT_YELLOW),
            "In Progress": (self.BLUE, "#DDEBF7"),
            "Rescued": (self.GREEN, "#E1F2E4"),
            "Closed": ("#666666", "#E8E8E8"),
            "Available": (self.GREEN, "#E1F2E4"),
            "Adopted": (self.BLUE, "#DDEBF7"),
            "Approved": (self.GREEN, "#E1F2E4"),
            "Rejected": (self.RED, "#F6E1E1"),
            "Cancelled": ("#666666", "#E8E8E8"),
        }

        self.current_user = None
        self.failed_logins = {}
        self.photo_cache = {}
        self.post_photo_path = None
        self.post_entries = {}

        try:
            self.db = Database()
        except OSError as error:
            messagebox.showerror(
                "Database Error",
                f"PetLink could not open its data file:\n{error}"
            )
            raise SystemExit(1)

        self.setup_styles()
        self.show_login()

    # =========================
    # GENERAL FUNCTIONS
    # =========================

    def setup_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "Treeview", rowheight=26, font=("Arial", 10),
            background=self.WHITE, fieldbackground=self.WHITE,
            foreground=self.TEXT_COLOR
        )
        style.configure(
            "Treeview.Heading", font=("Arial", 10, "bold"),
            background=self.NAV_COLOR, foreground=self.WHITE, relief="flat"
        )
        style.map("Treeview.Heading", background=[("active", self.BUTTON_COLOR)])
        style.map(
            "Treeview",
            background=[("selected", self.BUTTON_COLOR)],
            foreground=[("selected", self.WHITE)]
        )
        style.configure("TNotebook", background=self.BG_COLOR)
        style.configure("TNotebook.Tab", font=("Arial", 10, "bold"), padding=(14, 6))

    def clear_window(self):
        self.unbind_scroll()
        for widget in self.root.winfo_children():
            widget.destroy()

    def clear_content(self):
        if hasattr(self, "content_frame") and self.content_frame.winfo_exists():
            for widget in self.content_frame.winfo_children():
                widget.destroy()
            self.content_canvas.yview_moveto(0)

    def is_admin(self):
        return bool(self.current_user and self.db.is_admin(self.current_user))

    def run_action(self, function, *args):
        """Run a database action, turning save failures into a friendly message."""
        try:
            return function(*args)
        except OSError as error:
            return False, f"Could not save your data: {error}"

    def make_button(self, parent, text, command, color=None):
        return tk.Button(
            parent,
            text=text,
            command=command,
            font=("Arial", 10, "bold"),
            bg=color or self.BUTTON_COLOR,
            fg=self.WHITE,
            activebackground=self.NAV_COLOR,
            activeforeground=self.WHITE,
            relief="flat",
            cursor="hand2",
            padx=12,
            pady=7
        )

    def make_title(self, title, subtitle=""):
        tk.Label(
            self.content_frame,
            text=title,
            font=("Arial", 23, "bold"),
            bg=self.BG_COLOR,
            fg=self.NAV_COLOR
        ).pack(anchor="w", padx=25, pady=(20, 4))

        if subtitle:
            tk.Label(
                self.content_frame,
                text=subtitle,
                font=("Arial", 10),
                bg=self.BG_COLOR,
                fg=self.SUBTEXT_COLOR
            ).pack(anchor="w", padx=27, pady=(0, 15))

    def make_card(self, parent, title, value, description, color):
        card = tk.Frame(
            parent,
            bg=self.WHITE,
            highlightbackground="#D4E3E3",
            highlightthickness=1
        )

        tk.Frame(card, bg=color, height=5).pack(fill="x")

        tk.Label(
            card,
            text=title,
            font=("Arial", 10, "bold"),
            bg=self.WHITE,
            fg=self.SUBTEXT_COLOR
        ).pack(anchor="w", padx=14, pady=(12, 3))

        tk.Label(
            card,
            text=str(value),
            font=("Arial", 25, "bold"),
            bg=self.WHITE,
            fg=self.NAV_COLOR
        ).pack(anchor="w", padx=14)

        tk.Label(
            card,
            text=description,
            font=("Arial", 9),
            bg=self.WHITE,
            fg=self.SUBTEXT_COLOR,
            wraplength=180,
            justify="left"
        ).pack(anchor="w", padx=14, pady=(3, 14))

        return card

    def badge(self, parent, text, label_prefix=""):
        fg, bg = self.STATUS_STYLES.get(text, (self.SUBTEXT_COLOR, "#E8E8E8"))
        return tk.Label(
            parent,
            text=f"{label_prefix}{text}",
            font=("Arial", 9, "bold"),
            bg=bg,
            fg=fg,
            padx=8,
            pady=3
        )

    # ---------- photos ----------

    def _make_photo(self, path, max_w, max_h):
        try:
            if PIL_OK:
                with Image.open(path) as img:
                    img = ImageOps.exif_transpose(img).convert("RGB")
                    img.thumbnail((max_w, max_h))
                    return ImageTk.PhotoImage(img.copy())
            photo = tk.PhotoImage(file=str(path))
            factor = max(
                math.ceil(photo.width() / max_w),
                math.ceil(photo.height() / max_h), 1
            )
            return photo.subsample(factor) if factor > 1 else photo
        except Exception:
            return None

    def load_photo(self, filename, max_w, max_h):
        if not filename:
            return None
        key = (filename, max_w, max_h)
        if key not in self.photo_cache:
            path = PHOTO_DIR / Path(filename).name
            if not path.is_file():
                return None
            photo = self._make_photo(path, max_w, max_h)
            if photo is None:
                return None
            self.photo_cache[key] = photo
        return self.photo_cache[key]

    def photo_widget(self, parent, filename, width, height):
        box = tk.Frame(parent, width=width, height=height, bg="#DCECEC")
        box.pack_propagate(False)
        image = self.load_photo(filename, width, height)
        if image:
            label = tk.Label(box, image=image, bg="#DCECEC")
            label.image = image
        else:
            label = tk.Label(
                box, text="No photo", font=("Arial", 8),
                bg="#DCECEC", fg=self.SUBTEXT_COLOR
            )
        label.pack(expand=True)
        return box

    def show_details(self, title, lines, photo=None):
        win = tk.Toplevel(self.root)
        win.title(title)
        win.configure(bg=self.WHITE)
        win.transient(self.root)
        win.geometry(f"+{self.root.winfo_rootx() + 160}+{self.root.winfo_rooty() + 60}")

        tk.Label(
            win, text=title, font=("Arial", 15, "bold"),
            bg=self.WHITE, fg=self.NAV_COLOR
        ).pack(anchor="w", padx=20, pady=(16, 8))

        self.photo_widget(win, photo, 420, 300).pack(padx=20, pady=5)

        tk.Label(
            win, text="\n".join(lines), font=("Arial", 10), bg=self.WHITE,
            fg=self.TEXT_COLOR, justify="left", wraplength=420
        ).pack(anchor="w", padx=20, pady=10)

        self.make_button(win, "Close", win.destroy).pack(pady=(0, 16))

    # ---------- scrolling ----------

    def bind_scroll(self):
        self.root.bind_all("<MouseWheel>", self.on_mousewheel)
        self.root.bind_all("<Button-4>", self.on_mousewheel)
        self.root.bind_all("<Button-5>", self.on_mousewheel)

    def unbind_scroll(self):
        for sequence in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.root.unbind_all(sequence)

    def on_mousewheel(self, event):
        try:
            if not hasattr(self, "content_canvas") or not self.content_canvas.winfo_exists():
                return
            if isinstance(event.widget, (ttk.Treeview, tk.Listbox)):
                return
            if self.content_canvas.yview() == (0.0, 1.0):
                return
            if getattr(event, "num", None) == 4:
                step = -1
            elif getattr(event, "num", None) == 5:
                step = 1
            else:
                step = -1 if event.delta > 0 else 1
            self.content_canvas.yview_scroll(step * 2, "units")
        except tk.TclError:
            pass

    # =========================
    # LOGIN
    # =========================

    def show_login(self):
        self.clear_window()
        self.root.configure(bg=self.BG_COLOR)

        outer = tk.Frame(self.root, bg=self.BG_COLOR)
        outer.pack(expand=True, fill="both")

        panel = tk.Frame(
            outer,
            bg=self.WHITE,
            highlightbackground="#D4E3E3",
            highlightthickness=1
        )
        panel.place(
            relx=0.5, rely=0.5, anchor="center",
            width=420, height=520
        )

        tk.Label(
            panel,
            text="PETLINK",
            font=("Arial", 30, "bold"),
            bg=self.WHITE,
            fg=self.NAV_COLOR
        ).pack(pady=(30, 3))

        tk.Label(
            panel,
            text="AN ONLINE ADOPTION & TRACKING SYSTEM",
            font=("Arial", 8, "bold"),
            bg=self.WHITE,
            fg=self.SUBTEXT_COLOR
        ).pack(pady=(0, 20))

        tk.Label(
            panel,
            text="Welcome back!",
            font=("Arial", 18, "bold"),
            bg=self.WHITE,
            fg=self.TEXT_COLOR
        ).pack(pady=(0, 5))

        tk.Label(
            panel,
            text="Log in to continue to PetLink.",
            font=("Arial", 10),
            bg=self.WHITE,
            fg=self.SUBTEXT_COLOR
        ).pack(pady=(0, 20))

        tk.Label(
            panel,
            text="Username",
            font=("Arial", 10, "bold"),
            bg=self.WHITE,
            fg=self.TEXT_COLOR
        ).pack(anchor="w", padx=45)

        self.login_username = tk.Entry(
            panel, font=("Arial", 12), relief="solid", bd=1
        )
        self.login_username.pack(
            fill="x", padx=45, ipady=7, pady=(5, 12)
        )

        tk.Label(
            panel,
            text="Password",
            font=("Arial", 10, "bold"),
            bg=self.WHITE,
            fg=self.TEXT_COLOR
        ).pack(anchor="w", padx=45)

        self.login_password = tk.Entry(
            panel, font=("Arial", 12), show="*", relief="solid", bd=1
        )
        self.login_password.pack(
            fill="x", padx=45, ipady=7, pady=(5, 6)
        )

        self.login_show_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            panel,
            text="Show password",
            variable=self.login_show_var,
            command=self.toggle_login_password,
            bg=self.WHITE,
            fg=self.TEXT_COLOR,
            activebackground=self.WHITE
        ).pack(anchor="w", padx=42, pady=(0, 10))

        self.make_button(
            panel, "LOG IN", self.login, self.NAV_COLOR
        ).pack(fill="x", padx=45, pady=(0, 12))

        tk.Button(
            panel,
            text="Create an Account",
            command=self.show_register,
            font=("Arial", 10, "bold"),
            bg=self.WHITE,
            fg=self.NAV_COLOR,
            relief="flat",
            cursor="hand2"
        ).pack()

        self.login_password.bind("<Return>", lambda event: self.login())
        self.login_username.bind("<Return>", lambda event: self.login())
        self.login_username.focus_set()

    def toggle_login_password(self):
        self.login_password.configure(
            show="" if self.login_show_var.get() else "*"
        )

    def login(self):
        username = self.login_username.get().strip().lower()
        password = self.login_password.get()

        if not username or not password:
            messagebox.showwarning(
                "Missing Information",
                "Please enter your username and password."
            )
            return

        now = time.monotonic()
        record = self.failed_logins.get(username, {"count": 0, "locked_until": 0})
        if record["locked_until"] > now:
            wait = int(record["locked_until"] - now) + 1
            messagebox.showerror(
                "Too Many Attempts",
                f"Too many failed attempts. Please wait {wait} second(s) and try again."
            )
            return

        account = self.db.accounts.get(username)
        if account is not None:
            valid = verify_password(password, account["password"])
        else:
            verify_password(password, DUMMY_HASH)  # keep timing similar
            valid = False

        if not valid:
            record["count"] += 1
            if record["count"] >= MAX_LOGIN_ATTEMPTS:
                record = {"count": 0, "locked_until": now + LOCKOUT_SECONDS}
            self.failed_logins[username] = record
            messagebox.showerror(
                "Login Failed",
                "Incorrect username or password.\n\n"
                "If you do not have an account yet, please create one first."
            )
            return

        self.failed_logins.pop(username, None)
        self.current_user = username
        self.show_dashboard()

        if account.get("must_change_password"):
            self.root.after(150, lambda: self.open_change_password(forced=True))

    # =========================
    # CREATE ACCOUNT
    # =========================

    def show_register(self):
        self.clear_window()
        self.root.configure(bg=self.BG_COLOR)

        panel = tk.Frame(
            self.root,
            bg=self.WHITE,
            highlightbackground="#D4E3E3",
            highlightthickness=1
        )
        panel.place(
            relx=0.5, rely=0.5, anchor="center",
            width=450, height=600
        )

        tk.Label(
            panel,
            text="CREATE ACCOUNT",
            font=("Arial", 24, "bold"),
            bg=self.WHITE,
            fg=self.NAV_COLOR
        ).pack(pady=(22, 5))

        tk.Label(
            panel,
            text="Join the PetLink community!",
            font=("Arial", 10),
            bg=self.WHITE,
            fg=self.SUBTEXT_COLOR
        ).pack(pady=(0, 12))

        fields = [
            ("First Name", "first"),
            ("Last Name", "last"),
            (f"Password ({PASSWORD_MIN}-{PASSWORD_MAX} characters)", "password"),
            ("Confirm Password", "confirm")
        ]

        self.register_entries = {}

        for label_text, key in fields:
            tk.Label(
                panel,
                text=label_text,
                font=("Arial", 10, "bold"),
                bg=self.WHITE,
                fg=self.TEXT_COLOR
            ).pack(anchor="w", padx=45)

            entry = tk.Entry(
                panel,
                font=("Arial", 11),
                relief="solid",
                bd=1,
                show="*" if key in ("password", "confirm") else ""
            )
            entry.pack(
                fill="x", padx=45, ipady=5, pady=(4, 9)
            )
            self.register_entries[key] = entry

        self.show_password_var = tk.BooleanVar(value=False)

        tk.Checkbutton(
            panel,
            text="Show passwords",
            variable=self.show_password_var,
            command=self.toggle_password,
            bg=self.WHITE,
            fg=self.TEXT_COLOR,
            activebackground=self.WHITE
        ).pack(anchor="w", padx=42, pady=(0, 8))

        self.make_button(
            panel, "CREATE ACCOUNT", self.register, self.NAV_COLOR
        ).pack(fill="x", padx=45, pady=(3, 8))

        tk.Button(
            panel,
            text="Back to Login",
            command=self.show_login,
            font=("Arial", 10, "bold"),
            bg=self.WHITE,
            fg=self.NAV_COLOR,
            relief="flat",
            cursor="hand2"
        ).pack()

        self.register_entries["first"].focus_set()

    def toggle_password(self):
        show_char = "" if self.show_password_var.get() else "*"
        self.register_entries["password"].configure(show=show_char)
        self.register_entries["confirm"].configure(show=show_char)

    def register(self):
        first = self.register_entries["first"].get().strip()
        last = self.register_entries["last"].get().strip()
        password = self.register_entries["password"].get()
        confirm = self.register_entries["confirm"].get()

        if not first or not last or not password or not confirm:
            messagebox.showwarning(
                "Missing Information", "Please complete all fields."
            )
            return

        if not valid_name(first):
            messagebox.showwarning(
                "Invalid Name",
                "Please enter a valid first name (letters only, up to 30 characters)."
            )
            return

        if not valid_name(last):
            messagebox.showwarning(
                "Invalid Name",
                "Please enter a valid last name (letters only, up to 30 characters)."
            )
            return

        error = validate_password(password)
        if error:
            messagebox.showwarning("Invalid Password", error)
            return

        if password != confirm:
            messagebox.showerror(
                "Password Error", "The passwords do not match."
            )
            return

        try:
            username = self.db.create_account(first, last, password)
        except OSError as error:
            messagebox.showerror(
                "Save Error", f"Your account could not be saved:\n{error}"
            )
            return

        messagebox.showinfo(
            "Account Created",
            f"Your account was created successfully!\n\n"
            f"Your username is: {username}\n\n"
            "Please remember your username and password."
        )

        self.show_login()
        self.login_username.insert(0, username)
        self.login_password.focus_set()

    # =========================
    # CHANGE PASSWORD
    # =========================

    def open_change_password(self, forced=False):
        if not self.current_user:
            return

        dlg = tk.Toplevel(self.root)
        dlg.title("Change Password")
        dlg.configure(bg=self.WHITE)
        dlg.resizable(False, False)
        dlg.transient(self.root)
        dlg.geometry(f"+{self.root.winfo_rootx() + 280}+{self.root.winfo_rooty() + 110}")

        if forced:
            dlg.protocol("WM_DELETE_WINDOW", lambda: None)
            intro = ("For your security, you must choose a new password\n"
                     "before you continue.")
        else:
            intro = f"Choose a new password ({PASSWORD_MIN}-{PASSWORD_MAX} characters)."

        tk.Label(
            dlg, text="Change Password", font=("Arial", 15, "bold"),
            bg=self.WHITE, fg=self.NAV_COLOR
        ).pack(anchor="w", padx=25, pady=(18, 2))
        tk.Label(
            dlg, text=intro, font=("Arial", 9), bg=self.WHITE,
            fg=self.SUBTEXT_COLOR, justify="left"
        ).pack(anchor="w", padx=25, pady=(0, 10))

        entries = []
        for label_text in ("Current password", "New password", "Confirm new password"):
            tk.Label(
                dlg, text=label_text, font=("Arial", 10, "bold"),
                bg=self.WHITE, fg=self.TEXT_COLOR
            ).pack(anchor="w", padx=25)
            entry = tk.Entry(dlg, font=("Arial", 11), show="*", relief="solid", bd=1, width=30)
            entry.pack(fill="x", padx=25, ipady=4, pady=(3, 9))
            entries.append(entry)

        show_var = tk.BooleanVar(value=False)

        def toggle():
            for entry in entries:
                entry.configure(show="" if show_var.get() else "*")

        tk.Checkbutton(
            dlg, text="Show passwords", variable=show_var, command=toggle,
            bg=self.WHITE, fg=self.TEXT_COLOR, activebackground=self.WHITE
        ).pack(anchor="w", padx=22, pady=(0, 6))

        def submit():
            current, new, confirm = (e.get() for e in entries)
            account = self.db.accounts[self.current_user]
            if not verify_password(current, account["password"]):
                messagebox.showerror("Incorrect Password",
                                     "Your current password is incorrect.", parent=dlg)
                return
            error = validate_password(new)
            if error:
                messagebox.showwarning("Invalid Password", error, parent=dlg)
                return
            if new != confirm:
                messagebox.showerror("Password Error",
                                     "The new passwords do not match.", parent=dlg)
                return
            if new == current:
                messagebox.showwarning(
                    "Password Unchanged",
                    "Your new password must be different from the current one.",
                    parent=dlg
                )
                return
            try:
                self.db.set_password(self.current_user, new)
            except OSError as exc:
                messagebox.showerror("Save Error",
                                     f"Could not save the new password:\n{exc}", parent=dlg)
                return
            messagebox.showinfo("Password Changed",
                                "Your password was changed successfully.", parent=dlg)
            dlg.destroy()

        self.make_button(dlg, "CHANGE PASSWORD", submit, self.NAV_COLOR).pack(
            fill="x", padx=25, pady=(4, 6))
        if not forced:
            tk.Button(
                dlg, text="Cancel", command=dlg.destroy,
                font=("Arial", 10, "bold"), bg=self.WHITE, fg=self.NAV_COLOR,
                relief="flat", cursor="hand2"
            ).pack(pady=(0, 14))
        else:
            tk.Label(dlg, text="", bg=self.WHITE).pack(pady=4)

        dlg.bind("<Return>", lambda event: submit())
        entries[0].focus_set()
        try:
            dlg.wait_visibility()
            dlg.grab_set()
        except tk.TclError:
            pass
        self.root.wait_window(dlg)

    # =========================
    # MAIN LAYOUT
    # =========================

    def create_main_layout(self):
        self.root.configure(bg=self.BG_COLOR)

        # Responsive navigation: brand keeps its natural width while the
        # navigation buttons share the remaining horizontal space evenly.
        self.nav_frame = tk.Frame(self.root, bg=self.NAV_COLOR, height=65)
        self.nav_frame.pack(fill="x")
        self.nav_frame.pack_propagate(False)

        brand = tk.Label(
            self.nav_frame, text="PETLINK", font=("Arial", 19, "bold"),
            bg=self.NAV_COLOR, fg=self.WHITE
        )
        brand.pack(side="left", padx=(16, 12))

        if self.is_admin():
            nav_buttons = [
                ("Dashboard", self.show_dashboard),
                ("Users", lambda: self.show_admin_panel(0)),
                ("Pets", lambda: self.show_admin_panel(1)),
                ("Applications", lambda: self.show_admin_panel(2)),
                ("Stray Reports", lambda: self.show_admin_panel(3)),
                ("Stray Status", self.show_stray_status),
                ("Profile", self.show_profile),
                ("Log Out", self.logout)
            ]
        else:
            nav_buttons = [
                ("Dashboard", self.show_dashboard),
                ("Available Pets", self.show_profile_pet),
                ("Pet Posting", self.show_pet_posting),
                ("Stray Status", self.show_stray_status),
                ("Applications", self.show_application_form),
                ("Profile", self.show_profile),
                ("Log Out", self.logout)
            ]

        nav_items = tk.Frame(self.nav_frame, bg=self.NAV_COLOR)
        nav_items.pack(side="left", fill="both", expand=True, padx=(0, 8))
        for column, (text, command) in enumerate(nav_buttons):
            nav_items.grid_columnconfigure(column, weight=1, uniform="navigation")
            button = tk.Button(
                nav_items, text=text, command=command,
                font=("Arial", 9, "bold"), bg=self.NAV_COLOR, fg=self.WHITE,
                activebackground=self.BUTTON_COLOR, activeforeground=self.WHITE,
                relief="flat", cursor="hand2", padx=3, pady=5,
                wraplength=105
            )
            button.grid(row=0, column=column, sticky="nsew", padx=1, pady=7)

        body = tk.Frame(self.root, bg=self.BG_COLOR)
        body.pack(fill="both", expand=True)

        self.content_canvas = tk.Canvas(
            body, bg=self.BG_COLOR, highlightthickness=0
        )
        scrollbar = ttk.Scrollbar(
            body, orient="vertical", command=self.content_canvas.yview
        )
        self.content_canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.content_canvas.pack(side="left", fill="both", expand=True)

        self.content_frame = tk.Frame(self.content_canvas, bg=self.BG_COLOR)
        window = self.content_canvas.create_window(
            (0, 0), window=self.content_frame, anchor="nw"
        )
        self.content_frame.bind(
            "<Configure>",
            lambda e: self.content_canvas.configure(
                scrollregion=self.content_canvas.bbox("all"))
        )
        self.content_canvas.bind(
            "<Configure>",
            lambda e: self.content_canvas.itemconfigure(window, width=e.width)
        )
        self.bind_scroll()

    # =========================
    # DASHBOARD
    # =========================

    def show_dashboard(self):
        self.clear_window()
        self.root.geometry("1000x650")
        self.create_main_layout()

        if self.is_admin():
            self.build_admin_dashboard()
        else:
            self.build_user_dashboard()

    def build_user_dashboard(self):
        account = self.db.accounts[self.current_user]
        db = self.db

        available_count = sum(
            1 for pet in db.pets if pet["status"] == "Available"
        )

        my_applications = [
            app for app in db.applications
            if app["username"] == self.current_user
        ]
        my_pending = sum(1 for app in my_applications if app["status"] == "Pending")

        my_pet_ids = {p["id"] for p in db.pets if p["posted_by"] == self.current_user}
        incoming_pending = sum(
            1 for app in db.applications
            if app["pet_id"] in my_pet_ids and app["status"] == "Pending"
        )

        banner = tk.Frame(
            self.content_frame, bg=self.NAV_COLOR, height=120
        )
        banner.pack(fill="x", padx=22, pady=(20, 15))
        banner.pack_propagate(False)

        tk.Label(
            banner,
            text=f"Welcome back, {account['first_name']}!",
            font=("Arial", 22, "bold"),
            bg=self.NAV_COLOR,
            fg=self.WHITE
        ).pack(anchor="w", padx=22, pady=(20, 4))

        tk.Label(
            banner,
            text="Every pet deserves a safe home.",
            font=("Arial", 11),
            bg=self.NAV_COLOR,
            fg="#E0EEEE"
        ).pack(anchor="w", padx=24)

        cards_frame = tk.Frame(self.content_frame, bg=self.BG_COLOR)
        cards_frame.pack(fill="x", padx=22, pady=5)

        card_data = [
            ("AVAILABLE PETS", available_count, "Waiting for a home", self.GREEN),
            ("MY APPLICATIONS", len(my_applications),
             f"{my_pending} still pending", self.BUTTON_COLOR),
            ("PENDING REQUESTS", incoming_pending,
             "Adoption requests for your pets", self.YELLOW),
            ("MY PET POSTS", len(my_pet_ids), "Pets you posted", self.RED)
        ]

        for index, data in enumerate(card_data):
            card = self.make_card(
                cards_frame, data[0], data[1], data[2], data[3]
            )
            card.grid(row=0, column=index, sticky="nsew", padx=5, pady=5)
            cards_frame.grid_columnconfigure(index, weight=1, uniform="cards")

        lower = tk.Frame(self.content_frame, bg=self.BG_COLOR)
        lower.pack(fill="both", expand=True, padx=27, pady=(15, 10))

        recent_frame = tk.Frame(
            lower,
            bg=self.WHITE,
            highlightbackground="#D4E3E3",
            highlightthickness=1
        )
        recent_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))

        tk.Label(
            recent_frame,
            text="Recently Posted Pets",
            font=("Arial", 14, "bold"),
            bg=self.WHITE,
            fg=self.NAV_COLOR
        ).pack(anchor="w", padx=15, pady=(13, 8))

        if not db.pets:
            tk.Label(
                recent_frame,
                text="No pets have been posted yet.\nBe the first to post a pet!",
                font=("Arial", 10),
                bg=self.WHITE,
                fg=self.SUBTEXT_COLOR,
                justify="left"
            ).pack(anchor="w", padx=15, pady=8)
        else:
            for pet in db.pets[-3:][::-1]:
                tk.Frame(recent_frame, bg="#DCECEC", height=1).pack(
                    fill="x", padx=15, pady=3)

                row = tk.Frame(recent_frame, bg=self.WHITE)
                row.pack(fill="x", padx=15, pady=(2, 4))
                self.photo_widget(row, pet.get("photo"), 52, 52).pack(side="left")

                text_box = tk.Frame(row, bg=self.WHITE)
                text_box.pack(side="left", padx=10)

                tk.Label(
                    text_box,
                    text=f"{pet['name']}  •  {pet['breed']}",
                    font=("Arial", 10, "bold"),
                    bg=self.WHITE,
                    fg=self.TEXT_COLOR
                ).pack(anchor="w")

                tk.Label(
                    text_box,
                    text=f"Type: {pet.get('animal_type', 'Pet')}  |  "
                         f"Age: {pet['age']}  |  Status: {pet['status']}",
                    font=("Arial", 9),
                    bg=self.WHITE,
                    fg=self.SUBTEXT_COLOR
                ).pack(anchor="w", pady=(2, 0))

        quick_frame = tk.Frame(lower, bg="#DCECEC", width=230)
        quick_frame.pack(side="right", fill="y")
        quick_frame.pack_propagate(False)

        tk.Label(
            quick_frame,
            text="QUICK ACTIONS",
            font=("Arial", 13, "bold"),
            bg="#DCECEC",
            fg=self.NAV_COLOR
        ).pack(anchor="w", padx=15, pady=(15, 12))

        self.make_button(
            quick_frame, "Find a Pet", self.show_profile_pet
        ).pack(fill="x", padx=13, pady=5)

        self.make_button(
            quick_frame, "Post a Pet", self.show_pet_posting
        ).pack(fill="x", padx=13, pady=5)

        self.make_button(
            quick_frame,
            "Report a Stray",
            lambda: self.show_pet_posting("Stray Status Report")
        ).pack(fill="x", padx=13, pady=5)

        self.make_button(
            quick_frame,
            "View Applications",
            self.show_application_form
        ).pack(fill="x", padx=13, pady=(5, 15))

        tk.Label(
            self.content_frame,
            text="PETLINK  |  Helping pets find safe and loving homes",
            font=("Arial", 9),
            bg=self.BG_COLOR,
            fg=self.SUBTEXT_COLOR
        ).pack(pady=(0, 10))

    def build_admin_dashboard(self):
        db = self.db

        banner = tk.Frame(self.content_frame, bg=self.NAV_COLOR, height=120)
        banner.pack(fill="x", padx=22, pady=(20, 15))
        banner.pack_propagate(False)

        tk.Label(
            banner, text="Administrator Dashboard",
            font=("Arial", 22, "bold"), bg=self.NAV_COLOR, fg=self.WHITE
        ).pack(anchor="w", padx=22, pady=(20, 4))
        tk.Label(
            banner, text="Manage users, pet listings, applications and stray reports.",
            font=("Arial", 11), bg=self.NAV_COLOR, fg="#E0EEEE"
        ).pack(anchor="w", padx=24)

        users = sum(1 for a in db.accounts.values() if a.get("role") != "admin")
        pending_apps = sum(1 for a in db.applications if a["status"] == "Pending")
        open_reports = sum(
            1 for r in db.stray_reports if r["status"] in ("Pending", "In Progress")
        )

        cards_frame = tk.Frame(self.content_frame, bg=self.BG_COLOR)
        cards_frame.pack(fill="x", padx=22, pady=5)
        card_data = [
            ("USERS", users, "Registered members", self.BUTTON_COLOR),
            ("PET LISTINGS", len(db.pets), "All pets posted", self.GREEN),
            ("PENDING APPLICATIONS", pending_apps, "Awaiting a decision", self.YELLOW),
            ("OPEN STRAY REPORTS", open_reports, "Pending or in progress", self.RED),
        ]
        for index, data in enumerate(card_data):
            card = self.make_card(cards_frame, *data)
            card.grid(row=0, column=index, sticky="nsew", padx=5, pady=5)
            cards_frame.grid_columnconfigure(index, weight=1, uniform="cards")

        lower = tk.Frame(self.content_frame, bg=self.BG_COLOR)
        lower.pack(fill="both", expand=True, padx=27, pady=(15, 10))

        recent = tk.Frame(
            lower, bg=self.WHITE, highlightbackground="#D4E3E3", highlightthickness=1
        )
        recent.pack(side="left", fill="both", expand=True, padx=(0, 10))
        tk.Label(
            recent, text="Latest Stray Reports", font=("Arial", 14, "bold"),
            bg=self.WHITE, fg=self.NAV_COLOR
        ).pack(anchor="w", padx=15, pady=(13, 8))

        if not db.stray_reports:
            tk.Label(
                recent, text="No stray reports yet.", font=("Arial", 10),
                bg=self.WHITE, fg=self.SUBTEXT_COLOR
            ).pack(anchor="w", padx=15, pady=8)
        for report in db.stray_reports[-5:][::-1]:
            row = tk.Frame(recent, bg=self.WHITE)
            row.pack(fill="x", padx=15, pady=3)
            tk.Label(
                row, text=f"{report['name']}  •  {report['type']}  •  {report['location']}",
                font=("Arial", 10), bg=self.WHITE, fg=self.TEXT_COLOR
            ).pack(side="left")
            self.badge(row, report["status"]).pack(side="right")

        quick = tk.Frame(lower, bg="#DCECEC", width=230)
        quick.pack(side="right", fill="y")
        quick.pack_propagate(False)
        tk.Label(
            quick, text="MANAGE", font=("Arial", 13, "bold"),
            bg="#DCECEC", fg=self.NAV_COLOR
        ).pack(anchor="w", padx=15, pady=(15, 12))
        for text, tab in (("Users", 0), ("Pet Listings", 1),
                          ("Applications", 2), ("Stray Reports", 3)):
            self.make_button(
                quick, text, lambda t=tab: self.show_admin_panel(t)
            ).pack(fill="x", padx=13, pady=5)
        tk.Label(quick, text="", bg="#DCECEC").pack(pady=4)

    # =========================
    # AVAILABLE PETS
    # =========================

    def show_profile_pet(self):
        self.clear_content()
        self.make_title(
            "Available Pets",
            "Browse pets posted for adoption and send an adoption request."
        )

        search_row = tk.Frame(self.content_frame, bg=self.BG_COLOR)
        search_row.pack(fill="x", padx=25, pady=(0, 6))
        tk.Label(
            search_row, text="Search:", font=("Arial", 10, "bold"),
            bg=self.BG_COLOR, fg=self.TEXT_COLOR
        ).pack(side="left")
        self.pet_search = tk.StringVar()
        tk.Entry(
            search_row, textvariable=self.pet_search, font=("Arial", 10),
            relief="solid", bd=1, width=30
        ).pack(side="left", padx=8, ipady=3)
        tk.Label(
            search_row, text="(name, type or breed)", font=("Arial", 9),
            bg=self.BG_COLOR, fg=self.SUBTEXT_COLOR
        ).pack(side="left")

        self.pet_list_frame = tk.Frame(self.content_frame, bg=self.BG_COLOR)
        self.pet_list_frame.pack(fill="both", expand=True, padx=25, pady=5)
        self.pet_search.trace_add("write", lambda *args: self.render_available_pets())
        self.render_available_pets()

    def render_available_pets(self):
        if not self.pet_list_frame.winfo_exists():
            return
        for widget in self.pet_list_frame.winfo_children():
            widget.destroy()

        keyword = self.pet_search.get().strip().lower()
        available_pets = [
            pet for pet in self.db.pets if pet["status"] == "Available"
        ]
        total_available = len(available_pets)
        if keyword:
            available_pets = [
                pet for pet in available_pets
                if keyword in " ".join(
                    (pet["name"], pet.get("animal_type", ""), pet["breed"])
                ).lower()
            ]

        if not available_pets:
            message = (
                "No pets match your search." if total_available else
                "No available pets yet.\nYou can post a pet using the Pet Posting tab."
            )
            tk.Label(
                self.pet_list_frame, text=message, font=("Arial", 12),
                bg=self.BG_COLOR, fg=self.SUBTEXT_COLOR, justify="center"
            ).pack(pady=50)
            return

        for pet in reversed(available_pets):
            card = tk.Frame(
                self.pet_list_frame,
                bg=self.WHITE,
                highlightbackground="#D4E3E3",
                highlightthickness=1
            )
            card.pack(fill="x", pady=6)

            self.photo_widget(card, pet.get("photo"), 110, 110).pack(
                side="left", padx=12, pady=12)

            own_post = pet["posted_by"] == self.current_user
            if own_post:
                tk.Label(
                    card, text="YOUR POST", font=("Arial", 9, "bold"),
                    bg=self.WHITE, fg=self.SUBTEXT_COLOR
                ).pack(side="right", padx=20)
            else:
                self.make_button(
                    card, "Apply to Adopt",
                    lambda pet_id=pet["id"]: self.adopt_pet(pet_id)
                ).pack(side="right", padx=15, pady=15)

            info = tk.Frame(card, bg=self.WHITE)
            info.pack(side="left", fill="both", expand=True, padx=5, pady=12)

            tk.Label(
                info, text=pet["name"], font=("Arial", 14, "bold"),
                bg=self.WHITE, fg=self.NAV_COLOR
            ).pack(anchor="w")

            tk.Label(
                info,
                text=f"Type: {pet.get('animal_type', 'Unknown')}  |  "
                     f"Breed: {pet['breed']}  |  Age: {pet['age']}",
                font=("Arial", 10), bg=self.WHITE, fg=self.TEXT_COLOR
            ).pack(anchor="w", pady=3)

            if pet.get("info"):
                tk.Label(
                    info, text=pet["info"], font=("Arial", 9), bg=self.WHITE,
                    fg=self.TEXT_COLOR, justify="left", wraplength=450
                ).pack(anchor="w", pady=(0, 3))

            tk.Label(
                info, text=f"Posted by: {self.db.full_name(pet['posted_by'])}",
                font=("Arial", 9), bg=self.WHITE, fg=self.SUBTEXT_COLOR
            ).pack(anchor="w")

    def adopt_pet(self, pet_id):
        pet = self.db.get_pet(pet_id)
        if not pet:
            messagebox.showwarning("Pet Unavailable", "This pet no longer exists.")
            self.show_profile_pet()
            return

        # Rule checks first, so the person gets the right message before any prompt.
        if pet["posted_by"] == self.current_user:
            messagebox.showwarning(
                "Not Allowed",
                "You cannot adopt a pet that you posted yourself."
            )
            return
        if pet["status"] != "Available":
            messagebox.showwarning(
                "Pet Unavailable", "This pet is no longer available for adoption."
            )
            self.show_profile_pet()
            return
        if any(a["pet_id"] == pet_id and a["username"] == self.current_user
               and a["status"] == "Pending" for a in self.db.applications):
            messagebox.showinfo(
                "Already Applied",
                "You already have a pending application for this pet."
            )
            return

        if not messagebox.askyesno(
            "Adoption Request", f"Do you want to apply to adopt {pet['name']}?"
        ):
            return

        ok, message = self.run_action(self.db.apply_to_pet, self.current_user, pet_id)
        if ok:
            messagebox.showinfo(
                "Application Submitted",
                f"Your application for {pet['name']} has been submitted.\n"
                "Status: Pending"
            )
        else:
            messagebox.showwarning("Application Not Submitted", message)
            self.show_profile_pet()

    # =========================
    # PET POSTING
    # =========================

    def show_pet_posting(self, selected_category=None):
        self.clear_content()
        self.post_photo_path = None
        self.make_title(
            "Pet Posting",
            "Post a pet for adoption or report a stray animal in Pangasinan."
        )

        form = tk.Frame(
            self.content_frame,
            bg=self.WHITE,
            highlightbackground="#D4E3E3",
            highlightthickness=1
        )
        form.pack(fill="x", padx=25, pady=(0, 12))

        tk.Label(
            form,
            text="POST INFORMATION",
            font=("Arial", 13, "bold"),
            bg=self.WHITE,
            fg=self.NAV_COLOR
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=18, pady=(15, 10))

        tk.Label(
            form, text="Post Type", font=("Arial", 10, "bold"),
            bg=self.WHITE, fg=self.TEXT_COLOR
        ).grid(row=1, column=0, sticky="w", padx=18, pady=5)

        self.post_category = tk.StringVar(
            value=selected_category or "Pet for Adoption"
        )

        category_menu = tk.OptionMenu(
            form,
            self.post_category,
            "Pet for Adoption",
            "Stray Status Report",
            command=lambda value: self.update_post_fields()
        )
        category_menu.config(font=("Arial", 10), bg=self.BG_COLOR, relief="flat")
        category_menu.grid(row=1, column=1, sticky="ew", padx=18, pady=5)

        self.post_fields_frame = tk.Frame(form, bg=self.WHITE)
        self.post_fields_frame.grid(row=2, column=0, columnspan=2, sticky="ew")

        # Match the label column width used by the fields below so the
        # Post Type dropdown starts at the same horizontal position.
        form.grid_columnconfigure(0, minsize=190)
        form.grid_columnconfigure(1, weight=1, uniform="post_form")

        self.update_post_fields()

        self.make_button(
            form, "SUBMIT POST", self.post_pet, self.NAV_COLOR
        ).grid(row=3, column=0, columnspan=2, sticky="ew", padx=18, pady=(12, 18))

        tk.Label(
            self.content_frame,
            text="My Posts",
            font=("Arial", 15, "bold"),
            bg=self.BG_COLOR,
            fg=self.NAV_COLOR
        ).pack(anchor="w", padx=27, pady=(5, 5))

        self.my_posts_frame = tk.Frame(self.content_frame, bg=self.BG_COLOR)
        self.my_posts_frame.pack(fill="both", expand=True, padx=25, pady=(0, 10))

        self.display_my_posts()

    def update_post_fields(self):
        for widget in self.post_fields_frame.winfo_children():
            widget.destroy()

        self.post_entries = {}

        if self.post_category.get() == "Pet for Adoption":
            fields = [
                ("Pet Name", "name"),
                ("Age (years)", "age"),
                ("Breed", "breed"),
                ("Pet Type", "animal_type"),
                ("Additional Information", "info")
            ]
        else:
            fields = [
                ("Pet Name (if known)", "name"),
                ("Age (if known)", "age"),
                ("Pet Type", "animal_type"),
                ("Breed (if known)", "breed"),
                ("Location in Pangasinan", "location"),
                ("Additional Information", "info")
            ]

        for row, (label_text, key) in enumerate(fields):
            tk.Label(
                self.post_fields_frame, text=label_text, font=("Arial", 10, "bold"),
                bg=self.WHITE, fg=self.TEXT_COLOR
            ).grid(row=row, column=0, sticky="w", padx=18, pady=5)

            entry = tk.Entry(
                self.post_fields_frame, font=("Arial", 10), relief="solid", bd=1
            )
            entry.grid(row=row, column=1, sticky="ew", padx=18, pady=4, ipady=4)
            self.post_entries[key] = entry

        # Photo chooser
        photo_row = len(fields)
        tk.Label(
            self.post_fields_frame, text="Photo (optional)", font=("Arial", 10, "bold"),
            bg=self.WHITE, fg=self.TEXT_COLOR
        ).grid(row=photo_row, column=0, sticky="nw", padx=18, pady=8)

        photo_box = tk.Frame(self.post_fields_frame, bg=self.WHITE)
        photo_box.grid(row=photo_row, column=1, sticky="w", padx=18, pady=4)

        self.photo_preview_holder = tk.Frame(photo_box, bg=self.WHITE)
        self.photo_preview_holder.pack(side="left")

        controls = tk.Frame(photo_box, bg=self.WHITE)
        controls.pack(side="left", padx=12)
        self.make_button(controls, "Choose Photo...", self.choose_photo).pack(anchor="w")
        self.photo_name_label = tk.Label(
            controls, text="", font=("Arial", 9), bg=self.WHITE,
            fg=self.SUBTEXT_COLOR, wraplength=300, justify="left"
        )
        self.photo_name_label.pack(anchor="w", pady=(6, 0))
        tk.Button(
            controls, text="Remove photo", command=self.remove_photo,
            font=("Arial", 9), bg=self.WHITE, fg=self.RED,
            relief="flat", cursor="hand2"
        ).pack(anchor="w")
        tk.Label(
            controls,
            text="Allowed: " + ", ".join(PHOTO_EXTENSIONS) + "  (max 8 MB)",
            font=("Arial", 8), bg=self.WHITE, fg=self.SUBTEXT_COLOR
        ).pack(anchor="w")

        self.refresh_photo_preview()
        self.post_fields_frame.grid_columnconfigure(0, minsize=190)
        self.post_fields_frame.grid_columnconfigure(1, weight=1, uniform="post_form")

    def choose_photo(self):
        patterns = " ".join("*" + ext for ext in PHOTO_EXTENSIONS)
        path = filedialog.askopenfilename(
            title="Choose a photo",
            filetypes=[("Image files", patterns), ("All files", "*.*")]
        )
        if not path:
            return
        file = Path(path)
        if file.suffix.lower() not in PHOTO_EXTENSIONS:
            hint = "" if PIL_OK else "\n\nTip: install Pillow (pip install pillow) to use JPG photos."
            messagebox.showwarning(
                "Unsupported Photo",
                "Please choose a file of type: " + ", ".join(PHOTO_EXTENSIONS) + hint
            )
            return
        try:
            too_big = file.stat().st_size > MAX_PHOTO_BYTES
        except OSError:
            messagebox.showerror("Photo Error", "That file could not be read.")
            return
        if too_big:
            messagebox.showwarning("Photo Too Large", "Please choose a photo under 8 MB.")
            return
        if self._make_photo(file, 120, 120) is None:
            messagebox.showwarning("Invalid Photo", "That file is not a valid image.")
            return
        self.post_photo_path = str(file)
        self.refresh_photo_preview()

    def remove_photo(self):
        self.post_photo_path = None
        self.refresh_photo_preview()

    def refresh_photo_preview(self):
        if not self.photo_preview_holder.winfo_exists():
            return
        for widget in self.photo_preview_holder.winfo_children():
            widget.destroy()
        box = tk.Frame(self.photo_preview_holder, width=120, height=120, bg="#DCECEC")
        box.pack_propagate(False)
        box.pack()
        image = (self._make_photo(self.post_photo_path, 120, 120)
                 if self.post_photo_path else None)
        if image:
            label = tk.Label(box, image=image, bg="#DCECEC")
            label.image = image
            self.photo_name_label.config(text=Path(self.post_photo_path).name)
        else:
            label = tk.Label(box, text="No photo", font=("Arial", 8),
                             bg="#DCECEC", fg=self.SUBTEXT_COLOR)
            self.photo_name_label.config(text="")
        label.pack(expand=True)

    def post_pet(self):
        category = self.post_category.get()

        name = self.post_entries["name"].get().strip()
        age = self.post_entries["age"].get().strip()
        breed = self.post_entries["breed"].get().strip()
        animal_type = self.post_entries["animal_type"].get().strip()
        info = self.post_entries["info"].get().strip()

        if not animal_type:
            messagebox.showwarning(
                "Missing Pet Type",
                "Please type the pet type, such as Dog, Cat, Rabbit, or Bird."
            )
            return

        limits = [("Pet name", name, 40), ("Age", age, 30), ("Breed", breed, 40),
                  ("Pet type", animal_type, 30), ("Additional information", info, 300)]
        for label, value, maximum in limits:
            if len(value) > maximum:
                messagebox.showwarning(
                    "Text Too Long",
                    f"{label} must be {maximum} characters or fewer."
                )
                return

        if category == "Pet for Adoption":
            if not name or not age or not breed:
                messagebox.showwarning(
                    "Missing Information",
                    "For adoption posts, please enter the pet name, age, and breed."
                )
                return

            if not age.isdigit() or int(age) > 40:
                messagebox.showwarning(
                    "Invalid Age",
                    "Please enter the pet's age as a whole number of years (0-40)."
                )
                return

            photo_name = ""
            if self.post_photo_path:
                photo_name, error = store_photo(self.post_photo_path)
                if error:
                    messagebox.showerror("Photo Error", error)
                    return

            try:
                self.db.add_pet(
                    name, format_age(int(age)), breed, animal_type,
                    info, photo_name, self.current_user
                )
            except OSError as error:
                delete_photo_file(photo_name)
                messagebox.showerror("Save Error", f"Your post could not be saved:\n{error}")
                return

            messagebox.showinfo(
                "Post Submitted", f"{name} has been posted for adoption."
            )

        else:
            location = self.post_entries["location"].get().strip()

            if not location:
                messagebox.showwarning(
                    "Missing Location",
                    "Please enter the stray animal's location in Pangasinan."
                )
                return
            if len(location) > 80:
                messagebox.showwarning(
                    "Text Too Long", "Location must be 80 characters or fewer."
                )
                return

            photo_name = ""
            if self.post_photo_path:
                photo_name, error = store_photo(self.post_photo_path)
                if error:
                    messagebox.showerror("Photo Error", error)
                    return

            try:
                self.db.add_report(
                    name or "Unknown Pet", age or "Unknown", breed or "Unknown",
                    animal_type, location, info, photo_name, self.current_user
                )
            except OSError as error:
                delete_photo_file(photo_name)
                messagebox.showerror("Save Error", f"Your report could not be saved:\n{error}")
                return

            messagebox.showinfo(
                "Report Submitted",
                "The stray animal report has been submitted.\nStatus: Pending"
            )

        self.show_pet_posting(category)

    def display_my_posts(self):
        my_pets = [p for p in self.db.pets if p["posted_by"] == self.current_user]
        my_reports = [
            r for r in self.db.stray_reports if r["reported_by"] == self.current_user
        ]

        if not my_pets and not my_reports:
            tk.Label(
                self.my_posts_frame,
                text="You have not posted any pets or stray reports yet.",
                font=("Arial", 10), bg=self.BG_COLOR, fg=self.SUBTEXT_COLOR
            ).pack(anchor="w", pady=5)
            return

        for pet in reversed(my_pets):
            row = tk.Frame(self.my_posts_frame, bg=self.WHITE)
            row.pack(fill="x", pady=3)
            self.photo_widget(row, pet.get("photo"), 56, 56).pack(side="left", padx=8, pady=6)

            tk.Label(
                row,
                text=f"PET FOR ADOPTION: {pet['name']} | Type: {pet['animal_type']} | "
                     f"{pet['breed']} | {pet['age']}",
                font=("Arial", 10), bg=self.WHITE, fg=self.TEXT_COLOR, anchor="w"
            ).pack(side="left", padx=6)

            tk.Button(
                row, text="Delete", command=lambda pid=pet["id"]: self.delete_own_pet(pid),
                font=("Arial", 9, "bold"), bg=self.WHITE, fg=self.RED,
                relief="flat", cursor="hand2"
            ).pack(side="right", padx=10)
            self.badge(row, pet["status"]).pack(side="right", padx=6)

        for report in reversed(my_reports):
            row = tk.Frame(self.my_posts_frame, bg=self.WHITE)
            row.pack(fill="x", pady=3)
            self.photo_widget(row, report.get("photo"), 56, 56).pack(side="left", padx=8, pady=6)

            tk.Label(
                row,
                text=f"STRAY REPORT: {report['name']} | Type: {report['type']} | "
                     f"{report['location']}",
                font=("Arial", 10), bg=self.WHITE, fg=self.TEXT_COLOR, anchor="w"
            ).pack(side="left", padx=6)
            self.badge(row, report["status"]).pack(side="right", padx=10)

    def delete_own_pet(self, pet_id):
        pet = self.db.get_pet(pet_id)
        if not pet or pet["posted_by"] != self.current_user:
            return
        extra = ""
        if any(a["pet_id"] == pet_id for a in self.db.applications):
            extra = "\n\nAdoption applications for this pet will also be removed."
        if not messagebox.askyesno(
            "Delete Post", f"Delete the post for {pet['name']}?{extra}"
        ):
            return
        ok, message = self.run_action(self.db.delete_pet, pet_id)
        if not ok:
            messagebox.showerror("Delete Failed", message)
        self.show_pet_posting(self.post_category.get())

    # =========================
    # STRAY STATUS
    # =========================

    def show_stray_status(self):
        self.clear_content()
        self.make_title(
            "Stray Status Tracking",
            "View reported stray animals in Pangasinan and follow each report's progress."
        )

        if not self.db.stray_reports:
            tk.Label(
                self.content_frame,
                text="No stray reports yet.",
                font=("Arial", 12),
                bg=self.BG_COLOR,
                fg=self.SUBTEXT_COLOR
            ).pack(pady=60)
            return

        action_labels = {
            "In Progress": "Mark In Progress",
            "Rescued": "Mark Rescued",
            "Closed": "Close Report",
            "Pending": "Reopen Report",
        }

        for report in reversed(self.db.stray_reports):
            card = tk.Frame(
                self.content_frame,
                bg=self.WHITE,
                highlightbackground="#D4E3E3",
                highlightthickness=1
            )
            card.pack(fill="x", padx=25, pady=6)

            self.photo_widget(card, report.get("photo"), 110, 110).pack(
                side="left", padx=12, pady=12, anchor="n")

            body = tk.Frame(card, bg=self.WHITE)
            body.pack(side="left", fill="both", expand=True, pady=6)

            tk.Label(
                body, text=report["name"], font=("Arial", 14, "bold"),
                bg=self.WHITE, fg=self.NAV_COLOR
            ).pack(anchor="w", padx=5, pady=(6, 3))

            details = (
                f"Type: {report['type']}  |  "
                f"Breed: {report['breed']}  |  Age: {report['age']}\n"
                f"Location: {report['location']}, Pangasinan\n"
                f"Additional Information: {report['info'] or 'None'}\n"
                f"Reported by: {self.db.full_name(report['reported_by'])}  "
                f"on {fmt_dt(report['created_at'])}"
            )
            tk.Label(
                body, text=details, font=("Arial", 10), bg=self.WHITE,
                fg=self.TEXT_COLOR, justify="left", wraplength=620
            ).pack(anchor="w", padx=5, pady=(3, 6))

            status_row = tk.Frame(body, bg=self.WHITE)
            status_row.pack(anchor="w", padx=5, pady=(0, 4))
            self.badge(status_row, report["status"], "STATUS: ").pack(side="left")
            tk.Label(
                status_row, text=f"Last updated {fmt_dt(report['updated_at'])}",
                font=("Arial", 9), bg=self.WHITE, fg=self.SUBTEXT_COLOR
            ).pack(side="left", padx=10)

            history = report["history"][-3:]
            trail = "  →  ".join(
                f"{h['status']} ({fmt_dt(h['at'])})" for h in history
            )
            tk.Label(
                body, text=f"Progress: {trail}", font=("Arial", 8), bg=self.WHITE,
                fg=self.SUBTEXT_COLOR, justify="left", wraplength=620
            ).pack(anchor="w", padx=5)

            options = self.db.allowed_report_statuses(report, self.current_user)
            if options:
                actions = tk.Frame(body, bg=self.WHITE)
                actions.pack(anchor="w", padx=5, pady=(8, 8))
                for target in options:
                    self.make_button(
                        actions, action_labels[target],
                        lambda rid=report["id"], st=target: self.update_stray_status(rid, st)
                    ).pack(side="left", padx=(0, 8))

    def update_stray_status(self, report_id, new_status, refresh=None):
        if new_status == "Closed" and not messagebox.askyesno(
            "Close Report", "Close this report? This marks it as finished."
        ):
            return
        ok, message = self.run_action(
            self.db.set_report_status, report_id, new_status, self.current_user
        )
        if not ok:
            messagebox.showwarning("Status Not Updated", message)
        (refresh or self.show_stray_status)()

    # =========================
    # APPLICATION FORM
    # =========================

    def show_application_form(self):
        self.clear_content()
        self.make_title(
            "My Adoption Applications",
            "Check the status of your adoption requests and respond to requests for your pets."
        )

        db = self.db
        mine = [a for a in db.applications if a["username"] == self.current_user]
        my_pet_ids = {p["id"] for p in db.pets if p["posted_by"] == self.current_user}
        incoming = [a for a in db.applications if a["pet_id"] in my_pet_ids]

        if not mine and not incoming:
            tk.Label(
                self.content_frame,
                text="You have no adoption applications yet.\n"
                     "Visit Available Pets to apply for adoption.",
                font=("Arial", 11),
                bg=self.BG_COLOR,
                fg=self.SUBTEXT_COLOR,
                justify="center"
            ).pack(pady=50)
            return

        if mine:
            tk.Label(
                self.content_frame, text="Applications I Sent",
                font=("Arial", 14, "bold"), bg=self.BG_COLOR, fg=self.NAV_COLOR
            ).pack(anchor="w", padx=27, pady=(0, 2))

        for app in reversed(mine):
            pet = db.get_pet(app["pet_id"])
            card = tk.Frame(
                self.content_frame, bg=self.WHITE,
                highlightbackground="#D4E3E3", highlightthickness=1
            )
            card.pack(fill="x", padx=25, pady=7)

            self.photo_widget(card, pet.get("photo"), 80, 80).pack(
                side="left", padx=12, pady=10)

            if app["status"] == "Pending":
                tk.Button(
                    card, text="Cancel Application",
                    command=lambda aid=app["id"]: self.cancel_application(aid),
                    font=("Arial", 9, "bold"), bg=self.WHITE, fg=self.RED,
                    relief="flat", cursor="hand2"
                ).pack(side="right", padx=15)

            body = tk.Frame(card, bg=self.WHITE)
            body.pack(side="left", fill="both", expand=True, pady=8)

            tk.Label(
                body, text=f"Pet Name: {pet['name']}", font=("Arial", 13, "bold"),
                bg=self.WHITE, fg=self.NAV_COLOR
            ).pack(anchor="w", padx=5, pady=(4, 3))

            tk.Label(
                body,
                text=f"Pet Type: {pet['animal_type']}  |  "
                     f"Breed: {pet['breed']}  |  Age: {pet['age']}",
                font=("Arial", 10), bg=self.WHITE, fg=self.TEXT_COLOR
            ).pack(anchor="w", padx=5, pady=3)

            self.badge(body, app["status"], "APPLICATION STATUS: ").pack(
                anchor="w", padx=5, pady=(5, 4))

        if incoming:
            tk.Label(
                self.content_frame, text="Requests for My Pets",
                font=("Arial", 14, "bold"), bg=self.BG_COLOR, fg=self.NAV_COLOR
            ).pack(anchor="w", padx=27, pady=(14, 2))

        for app in reversed(incoming):
            pet = db.get_pet(app["pet_id"])
            card = tk.Frame(
                self.content_frame, bg=self.WHITE,
                highlightbackground="#D4E3E3", highlightthickness=1
            )
            card.pack(fill="x", padx=25, pady=7)

            self.photo_widget(card, pet.get("photo"), 80, 80).pack(
                side="left", padx=12, pady=10)

            if app["status"] == "Pending":
                buttons = tk.Frame(card, bg=self.WHITE)
                buttons.pack(side="right", padx=15)
                self.make_button(
                    buttons, "Approve", lambda aid=app["id"]: self.decide_application(aid, "Approved"),
                    self.GREEN
                ).pack(side="left", padx=4)
                self.make_button(
                    buttons, "Reject", lambda aid=app["id"]: self.decide_application(aid, "Rejected"),
                    self.RED
                ).pack(side="left", padx=4)

            body = tk.Frame(card, bg=self.WHITE)
            body.pack(side="left", fill="both", expand=True, pady=8)

            tk.Label(
                body, text=f"{pet['name']} — requested by {db.full_name(app['username'])}",
                font=("Arial", 12, "bold"), bg=self.WHITE, fg=self.NAV_COLOR
            ).pack(anchor="w", padx=5, pady=(4, 3))
            tk.Label(
                body,
                text=f"Username: {app['username']}  |  Sent: {fmt_dt(app['created_at'])}",
                font=("Arial", 10), bg=self.WHITE, fg=self.TEXT_COLOR
            ).pack(anchor="w", padx=5, pady=3)
            self.badge(body, app["status"], "STATUS: ").pack(anchor="w", padx=5, pady=(5, 4))

    def cancel_application(self, app_id):
        if not messagebox.askyesno("Cancel Application", "Cancel this application?"):
            return
        ok, message = self.run_action(
            self.db.cancel_application, app_id, self.current_user
        )
        if not ok:
            messagebox.showwarning("Not Cancelled", message)
        self.show_application_form()

    def decide_application(self, app_id, decision):
        app = self.db.get_application(app_id)
        if not app:
            self.show_application_form()
            return
        pet = self.db.get_pet(app["pet_id"])
        extra = ""
        if decision == "Approved":
            extra = (f"\n\n{pet['name']} will be marked as Adopted and all other "
                     "pending requests for this pet will be rejected.")
        if not messagebox.askyesno(
            f"{decision[:-1]}e Application" if decision == "Approved" else "Reject Application",
            f"{'Approve' if decision == 'Approved' else 'Reject'} "
            f"{self.db.full_name(app['username'])}'s request for {pet['name']}?{extra}"
        ):
            return
        ok, message = self.run_action(
            self.db.decide_application, app_id, decision, self.current_user
        )
        if not ok:
            messagebox.showwarning("Not Updated", message)
        self.show_application_form()

    # =========================
    # PROFILE
    # =========================

    def show_profile(self):
        self.clear_content()
        self.make_title(
            "My Profile",
            "View your account information and PetLink activity."
        )

        account = self.db.accounts[self.current_user]
        db = self.db

        panel = tk.Frame(
            self.content_frame,
            bg=self.WHITE,
            highlightbackground="#D4E3E3",
            highlightthickness=1
        )
        panel.pack(fill="x", padx=25, pady=5)

        tk.Label(
            panel, text="ACCOUNT INFORMATION", font=("Arial", 13, "bold"),
            bg=self.WHITE, fg=self.NAV_COLOR
        ).pack(anchor="w", padx=20, pady=(18, 10))

        details = [
            ("First Name", account["first_name"]),
            ("Last Name", account["last_name"]),
            ("Username", self.current_user),
            ("Account Type", "Administrator" if self.is_admin() else "Member"),
            ("Member Since", fmt_dt(account.get("created_at", "")))
        ]

        for label_text, value in details:
            row = tk.Frame(panel, bg=self.WHITE)
            row.pack(fill="x", padx=20, pady=5)
            tk.Label(
                row, text=label_text + ":", font=("Arial", 10, "bold"),
                bg=self.WHITE, fg=self.TEXT_COLOR, width=16, anchor="w"
            ).pack(side="left")
            tk.Label(
                row, text=value, font=("Arial", 10),
                bg=self.WHITE, fg=self.SUBTEXT_COLOR
            ).pack(side="left")

        tk.Label(
            panel, text="MY ACTIVITY" if not self.is_admin() else "SYSTEM OVERVIEW",
            font=("Arial", 13, "bold"), bg=self.WHITE, fg=self.NAV_COLOR
        ).pack(anchor="w", padx=20, pady=(20, 8))

        if self.is_admin():
            activity = [
                f"Registered members: {sum(1 for a in db.accounts.values() if a.get('role') != 'admin')}",
                f"Pet listings: {len(db.pets)}",
                f"Adoption applications: {len(db.applications)}",
                f"Stray reports: {len(db.stray_reports)}",
            ]
        else:
            own_pet_count = sum(1 for p in db.pets if p["posted_by"] == self.current_user)
            own_report_count = sum(
                1 for r in db.stray_reports if r["reported_by"] == self.current_user
            )
            own_apps = [a for a in db.applications if a["username"] == self.current_user]
            adopted = sum(1 for a in own_apps if a["status"] == "Approved")
            rescued = sum(
                1 for r in db.stray_reports
                if r["reported_by"] == self.current_user and r["status"] == "Rescued"
            )
            activity = [
                f"Pets posted for adoption: {own_pet_count}",
                f"Stray reports submitted: {own_report_count}",
                f"Adoption applications: {len(own_apps)}",
                f"Adopted pets: {adopted}",
                f"Rescued pets: {rescued}"
            ]

        for item in activity:
            tk.Label(
                panel, text="• " + item, font=("Arial", 10),
                bg=self.WHITE, fg=self.TEXT_COLOR
            ).pack(anchor="w", padx=22, pady=3)

        self.make_button(
            panel, "Change Password", self.open_change_password, self.NAV_COLOR
        ).pack(anchor="w", padx=20, pady=(18, 20))

    # =========================
    # ADMIN PANEL
    # =========================

    def build_table(self, parent, columns):
        wrap = tk.Frame(parent, bg=self.WHITE)
        wrap.pack(fill="both", expand=True, padx=10, pady=(10, 5))
        tree = ttk.Treeview(
            wrap, columns=[c[0] for c in columns], show="headings",
            height=11, selectmode="browse"
        )
        for key, heading, width in columns:
            tree.heading(key, text=heading)
            tree.column(key, width=width, anchor="w")
        scroll = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        return tree

    def button_row(self, parent):
        row = tk.Frame(parent, bg=self.WHITE)
        row.pack(fill="x", padx=10, pady=(0, 12))
        return row

    def selected_id(self, tree, as_int=True):
        selection = tree.selection()
        if not selection:
            messagebox.showinfo("Select a Row", "Please select a row in the table first.")
            return None
        return int(selection[0]) if as_int else selection[0]

    def show_admin_panel(self, tab=0):
        if not self.is_admin():
            return
        self.clear_content()
        self.make_title(
            "Administrator Panel",
            "Manage users, pet listings, adoption applications and stray reports."
        )
        notebook = ttk.Notebook(self.content_frame)
        notebook.pack(fill="both", expand=True, padx=25, pady=(0, 15))

        self.build_users_tab(notebook)
        self.build_pets_tab(notebook)
        self.build_applications_tab(notebook)
        self.build_reports_tab(notebook)
        notebook.select(max(0, min(tab, 3)))

    # ---------- users ----------

    def build_users_tab(self, notebook):
        tab = tk.Frame(notebook, bg=self.WHITE)
        notebook.add(tab, text="  Users  ")
        tree = self.build_table(tab, [
            ("username", "Username", 130), ("name", "Full Name", 170),
            ("role", "Role", 80), ("pets", "Pets", 60),
            ("apps", "Applications", 95), ("reports", "Reports", 70),
            ("created", "Created", 160)
        ])

        def refresh():
            tree.delete(*tree.get_children())
            for username, acc in sorted(self.db.accounts.items()):
                tree.insert("", "end", iid=username, values=(
                    username, self.db.full_name(username),
                    "Admin" if acc.get("role") == "admin" else "Member",
                    sum(1 for p in self.db.pets if p["posted_by"] == username),
                    sum(1 for a in self.db.applications if a["username"] == username),
                    sum(1 for r in self.db.stray_reports if r["reported_by"] == username),
                    fmt_dt(acc.get("created_at", ""))
                ))

        def reset_password():
            username = self.selected_id(tree, as_int=False)
            if not username:
                return
            if username == self.current_user:
                messagebox.showinfo(
                    "Use Profile", "Change your own password from the Profile page.")
                return
            if not messagebox.askyesno(
                "Reset Password",
                f"Generate a temporary password for '{username}'?\n"
                "They will be required to change it at their next login."
            ):
                return
            alphabet = string.ascii_letters + string.digits
            temp = "".join(secrets.choice(alphabet) for _ in range(10))
            try:
                self.db.set_password(username, temp, must_change=True)
            except OSError as error:
                messagebox.showerror("Save Error", f"Could not save: {error}")
                return
            messagebox.showinfo(
                "Temporary Password",
                f"Temporary password for '{username}':\n\n{temp}\n\n"
                "Share it securely. It is shown only once."
            )

        def delete_user():
            username = self.selected_id(tree, as_int=False)
            if not username:
                return
            if username == self.current_user or self.db.is_admin(username):
                messagebox.showwarning(
                    "Not Allowed", "The administrator account cannot be deleted.")
                return
            pets = sum(1 for p in self.db.pets if p["posted_by"] == username)
            apps = sum(1 for a in self.db.applications if a["username"] == username)
            reports = sum(1 for r in self.db.stray_reports if r["reported_by"] == username)
            if not messagebox.askyesno(
                "Delete User",
                f"Delete '{username}' permanently?\n\nThis also removes their "
                f"{pets} pet post(s), {apps} application(s) and {reports} stray report(s).\n"
                "This cannot be undone.",
                icon="warning"
            ):
                return
            ok, message = self.run_action(self.db.delete_user, username)
            if not ok:
                messagebox.showerror("Delete Failed", message)
            refresh()

        row = self.button_row(tab)
        self.make_button(row, "Reset Password", reset_password).pack(side="left", padx=(0, 8))
        self.make_button(row, "Delete User", delete_user, self.RED).pack(side="left", padx=(0, 8))
        self.make_button(row, "Refresh", refresh, self.NAV_COLOR).pack(side="left")
        refresh()

    # ---------- pets ----------

    def build_pets_tab(self, notebook):
        tab = tk.Frame(notebook, bg=self.WHITE)
        notebook.add(tab, text="  Pet Listings  ")
        tree = self.build_table(tab, [
            ("id", "ID", 45), ("name", "Name", 130), ("type", "Type", 90),
            ("breed", "Breed", 130), ("age", "Age", 110), ("status", "Status", 90),
            ("poster", "Posted By", 130), ("date", "Posted", 150)
        ])

        def refresh():
            tree.delete(*tree.get_children())
            for pet in reversed(self.db.pets):
                tree.insert("", "end", iid=str(pet["id"]), values=(
                    pet["id"], pet["name"], pet.get("animal_type", ""), pet["breed"],
                    pet["age"], pet["status"], pet["posted_by"],
                    fmt_dt(pet.get("created_at", ""))
                ))

        def view():
            pet_id = self.selected_id(tree)
            pet = self.db.get_pet(pet_id) if pet_id else None
            if not pet:
                return
            lines = [
                f"Type: {pet.get('animal_type', '')}", f"Breed: {pet['breed']}",
                f"Age: {pet['age']}", f"Status: {pet['status']}",
                f"Posted by: {self.db.full_name(pet['posted_by'])} ({pet['posted_by']})",
                f"Information: {pet.get('info') or 'None'}"
            ]
            if pet.get("adopted_by"):
                lines.insert(4, f"Adopted by: {self.db.full_name(pet['adopted_by'])}")
            self.show_details(pet["name"], lines, pet.get("photo"))

        def remove():
            pet_id = self.selected_id(tree)
            pet = self.db.get_pet(pet_id) if pet_id else None
            if not pet:
                return
            if not messagebox.askyesno(
                "Remove Listing",
                f"Remove the listing for {pet['name']}?\n"
                "Applications for this pet will also be deleted.", icon="warning"
            ):
                return
            ok, message = self.run_action(self.db.delete_pet, pet_id)
            if not ok:
                messagebox.showerror("Remove Failed", message)
            refresh()

        row = self.button_row(tab)
        self.make_button(row, "View Details", view).pack(side="left", padx=(0, 8))
        self.make_button(row, "Remove Listing", remove, self.RED).pack(side="left", padx=(0, 8))
        self.make_button(row, "Refresh", refresh, self.NAV_COLOR).pack(side="left")
        refresh()

    # ---------- applications ----------

    def build_applications_tab(self, notebook):
        tab = tk.Frame(notebook, bg=self.WHITE)
        notebook.add(tab, text="  Applications  ")
        tree = self.build_table(tab, [
            ("id", "ID", 45), ("pet", "Pet", 130), ("applicant", "Applicant", 150),
            ("owner", "Pet Owner", 130), ("status", "Status", 90),
            ("sent", "Submitted", 160), ("by", "Decided By", 110)
        ])

        def refresh():
            tree.delete(*tree.get_children())
            for app in reversed(self.db.applications):
                pet = self.db.get_pet(app["pet_id"])
                tree.insert("", "end", iid=str(app["id"]), values=(
                    app["id"], pet["name"] if pet else "(removed)", app["username"],
                    pet["posted_by"] if pet else "", app["status"],
                    fmt_dt(app["created_at"]), app.get("decided_by", "")
                ))

        def decide(decision):
            app_id = self.selected_id(tree)
            if not app_id:
                return
            if not messagebox.askyesno(
                "Confirm", f"{'Approve' if decision == 'Approved' else 'Reject'} application #{app_id}?"
            ):
                return
            ok, message = self.run_action(
                self.db.decide_application, app_id, decision, self.current_user
            )
            if not ok:
                messagebox.showwarning("Not Updated", message)
            refresh()

        def delete():
            app_id = self.selected_id(tree)
            if not app_id:
                return
            if not messagebox.askyesno(
                "Delete Record",
                f"Delete application #{app_id}?\nIf it was approved, the pet becomes Available again.",
                icon="warning"
            ):
                return
            ok, message = self.run_action(self.db.delete_application, app_id)
            if not ok:
                messagebox.showerror("Delete Failed", message)
            refresh()

        row = self.button_row(tab)
        self.make_button(row, "Approve", lambda: decide("Approved"), self.GREEN).pack(side="left", padx=(0, 8))
        self.make_button(row, "Reject", lambda: decide("Rejected"), self.YELLOW).pack(side="left", padx=(0, 8))
        self.make_button(row, "Delete Record", delete, self.RED).pack(side="left", padx=(0, 8))
        self.make_button(row, "Refresh", refresh, self.NAV_COLOR).pack(side="left")
        refresh()

    # ---------- stray reports ----------

    def build_reports_tab(self, notebook):
        tab = tk.Frame(notebook, bg=self.WHITE)
        notebook.add(tab, text="  Stray Reports  ")
        tree = self.build_table(tab, [
            ("id", "ID", 45), ("name", "Name", 110), ("type", "Type", 80),
            ("location", "Location", 140), ("status", "Status", 90),
            ("by", "Reported By", 110), ("updated", "Last Update", 160)
        ])

        def refresh():
            tree.delete(*tree.get_children())
            for report in reversed(self.db.stray_reports):
                tree.insert("", "end", iid=str(report["id"]), values=(
                    report["id"], report["name"], report["type"], report["location"],
                    report["status"], report["reported_by"], fmt_dt(report["updated_at"])
                ))

        def view():
            report_id = self.selected_id(tree)
            report = self.db.get_report(report_id) if report_id else None
            if not report:
                return
            history = [f"   • {h['status']} — {fmt_dt(h['at'])} by {h['by']}"
                       for h in report["history"]]
            lines = [
                f"Type: {report['type']}   Breed: {report['breed']}   Age: {report['age']}",
                f"Location: {report['location']}, Pangasinan",
                f"Status: {report['status']}",
                f"Reported by: {self.db.full_name(report['reported_by'])}",
                f"Information: {report['info'] or 'None'}",
                "History:", *history
            ]
            self.show_details(f"Stray Report: {report['name']}", lines, report.get("photo"))

        def set_status(new_status):
            report_id = self.selected_id(tree)
            if not report_id:
                return
            ok, message = self.run_action(
                self.db.set_report_status, report_id, new_status, self.current_user
            )
            if not ok:
                messagebox.showwarning("Status Not Updated", message)
            refresh()

        def delete():
            report_id = self.selected_id(tree)
            if not report_id:
                return
            if not messagebox.askyesno(
                "Delete Report", f"Delete stray report #{report_id} permanently?", icon="warning"
            ):
                return
            ok, message = self.run_action(self.db.delete_report, report_id)
            if not ok:
                messagebox.showerror("Delete Failed", message)
            refresh()

        row = self.button_row(tab)
        self.make_button(row, "View", view).pack(side="left", padx=(0, 6))
        self.make_button(row, "In Progress", lambda: set_status("In Progress"), self.BLUE).pack(side="left", padx=(0, 6))
        self.make_button(row, "Rescued", lambda: set_status("Rescued"), self.GREEN).pack(side="left", padx=(0, 6))
        self.make_button(row, "Closed", lambda: set_status("Closed"), "#666666").pack(side="left", padx=(0, 6))
        self.make_button(row, "Reopen", lambda: set_status("Pending"), self.YELLOW).pack(side="left", padx=(0, 6))
        self.make_button(row, "Delete", delete, self.RED).pack(side="left", padx=(0, 6))
        self.make_button(row, "Refresh", refresh, self.NAV_COLOR).pack(side="left")
        refresh()

    # =========================
    # LOG OUT
    # =========================

    def logout(self):
        confirm = messagebox.askyesno(
            "Log Out",
            "Are you sure you want to log out?"
        )

        if confirm:
            self.current_user = None
            self.show_login()


if __name__ == "__main__":
    root = tk.Tk()
    app = PetLink(root)
    root.mainloop()
