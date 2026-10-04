import os
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
import xml.etree.ElementTree as ET


SECRET_TAGS = {
    "password",
    "passwd",
    "secret",
    "httpdpassword",
    "snmp_password",
    "rocommunity",
    "community",
    "privkey",
    "privatekey",
    "prv",
    "apikey",
    "apikeys",
    "api_key",
    "token",
    "authkey",
    "authorizedkeys",
    "otp_seed",
    "psk",
    "pre-shared-key",
    "tlskey",
    "tlsauth",
    "ta_key",
    "adv_dhcp6_key_info_statement_secret",
}

CREDENTIAL_CONTEXTS = {
    "dyndns",
    "ddclient",
    "monit",
    "proxy",
    "authserver",
    "ldap",
    "radius",
    "hasync",
    "account",
    "accounts",
}

USERNAME_TAGS = {"username", "user", "httpdusername"}
AUDIT_PARENT_TAGS = {"created", "updated", "revision"}


def local_name(tag):
    """Return a namespace-free, lower-case XML tag name."""
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1].lower()


def has_content(element):
    """True when an element or any child below it contains non-whitespace text."""
    return bool("".join(element.itertext()).strip())


def clear_element(element):
    """Equivalent to setting XmlNode.InnerText = '' in the PowerShell version."""
    for child in list(element):
        element.remove(child)
    element.text = ""


def has_ancestor_in(element, parent_map, names):
    parent = parent_map.get(element)
    while parent is not None:
        if local_name(parent.tag) in names:
            return True
        parent = parent_map.get(parent)
    return False


def sanitize_tree(tree, strip_audit_usernames=False):
    root = tree.getroot()
    parent_map = {child: parent for parent in root.iter() for child in parent}

    stats = {
        "secret_fields": 0,
        "credential_usernames": 0,
        "geoip_urls": 0,
        "audit_usernames": 0,
    }

    # Blank known secret/credential values.
    for element in root.iter():
        if local_name(element.tag) in SECRET_TAGS:
            if has_content(element):
                stats["secret_fields"] += 1
            clear_element(element)

    # Blank usernames only when they appear under known credential/login contexts.
    for element in root.iter():
        if local_name(element.tag) in USERNAME_TAGS:
            if has_ancestor_in(element, parent_map, CREDENTIAL_CONTEXTS):
                if has_content(element):
                    stats["credential_usernames"] += 1
                clear_element(element)

    # GeoIP URLs can embed a MaxMind license key.
    for geoip in root.iter():
        if local_name(geoip.tag) != "geoip":
            continue
        for child in list(geoip):
            if local_name(child.tag) == "url":
                if has_content(child):
                    stats["geoip_urls"] += 1
                clear_element(child)

    # Optional public-posting mode: remove audit-history usernames/IPs.
    if strip_audit_usernames:
        for parent in root.iter():
            if local_name(parent.tag) not in AUDIT_PARENT_TAGS:
                continue
            for child in list(parent):
                if local_name(child.tag) == "username":
                    if has_content(child):
                        stats["audit_usernames"] += 1
                    clear_element(child)

    # Fail-safe validation: stop instead of saving if a known secret remains.
    remaining = []

    for element in root.iter():
        name = local_name(element.tag)
        if name in SECRET_TAGS and has_content(element):
            remaining.append(name)

        if name in USERNAME_TAGS:
            if has_ancestor_in(element, parent_map, CREDENTIAL_CONTEXTS) and has_content(element):
                remaining.append(name)

    for geoip in root.iter():
        if local_name(geoip.tag) != "geoip":
            continue
        for child in list(geoip):
            if local_name(child.tag) == "url" and has_content(child):
                remaining.append("geoip/url")

    if remaining:
        names = ", ".join(sorted(set(remaining)))
        raise ValueError(
            "Sanitizer stopped: one or more known credential fields still contain data: "
            + names
        )

    return stats


def load_and_sanitize(input_path, strip_audit_usernames=False):
    parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
    tree = ET.parse(input_path, parser=parser)
    stats = sanitize_tree(tree, strip_audit_usernames=strip_audit_usernames)
    return tree, stats


class OPNsenseCleanerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("OPNsense Config Sanitizer")
        self.geometry("720x390")
        self.minsize(680, 360)

        self.input_var = tk.StringVar()
        self.output_var = tk.StringVar(value="No sanitized file saved yet.")
        self.strip_audit_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="Select an OPNsense XML configuration to begin.")
        self.last_output_path = None

        self._build_ui()

    def _build_ui(self):
        outer = ttk.Frame(self, padding=20)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)

        title = ttk.Label(outer, text="OPNsense Config Sanitizer", font=("Segoe UI", 18, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 6))

        subtitle = ttk.Label(
            outer,
            text="Select an OPNsense config.xml, remove known credentials/secrets, then save a sanitized copy.",
            wraplength=660,
        )
        subtitle.grid(row=1, column=0, sticky="w", pady=(0, 18))

        input_frame = ttk.LabelFrame(outer, text="Input XML", padding=12)
        input_frame.grid(row=2, column=0, sticky="ew")
        input_frame.columnconfigure(0, weight=1)

        self.input_entry = ttk.Entry(input_frame, textvariable=self.input_var)
        self.input_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        ttk.Button(input_frame, text="Browse...", command=self.browse_input).grid(row=0, column=1)

        ttk.Checkbutton(
            outer,
            text="Strip audit-history usernames/IPs (recommended only for public-posting copies)",
            variable=self.strip_audit_var,
        ).grid(row=3, column=0, sticky="w", pady=(14, 14))

        button_frame = ttk.Frame(outer)
        button_frame.grid(row=4, column=0, sticky="w")

        ttk.Button(
            button_frame,
            text="Sanitize and Save As...",
            command=self.sanitize_and_save,
        ).pack(side="left")

        self.open_folder_button = ttk.Button(
            button_frame,
            text="Open Output Folder",
            command=self.open_output_folder,
            state="disabled",
        )
        self.open_folder_button.pack(side="left", padx=(10, 0))

        output_frame = ttk.LabelFrame(outer, text="Output", padding=12)
        output_frame.grid(row=5, column=0, sticky="ew", pady=(18, 0))
        output_frame.columnconfigure(0, weight=1)

        ttk.Label(output_frame, textvariable=self.output_var, wraplength=630).grid(row=0, column=0, sticky="w")

        status_frame = ttk.LabelFrame(outer, text="Status", padding=12)
        status_frame.grid(row=6, column=0, sticky="ew", pady=(12, 0))
        status_frame.columnconfigure(0, weight=1)

        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, wraplength=630)
        self.status_label.grid(row=0, column=0, sticky="w")

    def browse_input(self):
        filename = filedialog.askopenfilename(
            title="Select OPNsense configuration XML",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")],
        )
        if filename:
            self.input_var.set(filename)
            self.status_var.set("Ready to sanitize. The original XML will not be modified.")

    def sanitize_and_save(self):
        raw_input = self.input_var.get().strip().strip('"')
        if not raw_input:
            messagebox.showwarning("No input file", "Select an OPNsense XML file first.")
            return

        input_path = Path(raw_input)
        if not input_path.is_file():
            messagebox.showerror("Input file not found", f"The selected file does not exist:\n\n{input_path}")
            return

        try:
            tree, stats = load_and_sanitize(
                input_path,
                strip_audit_usernames=self.strip_audit_var.get(),
            )
        except ET.ParseError as exc:
            messagebox.showerror("Invalid XML", f"The selected file could not be parsed as XML:\n\n{exc}")
            self.status_var.set("Sanitization failed: invalid XML.")
            return
        except Exception as exc:
            messagebox.showerror("Sanitization failed", str(exc))
            self.status_var.set("Sanitization failed. No output file was created.")
            return

        suggested_name = f"{input_path.stem}-sanitized.xml"
        output_filename = filedialog.asksaveasfilename(
            title="Save sanitized OPNsense configuration",
            initialdir=str(input_path.parent),
            initialfile=suggested_name,
            defaultextension=".xml",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")],
        )

        if not output_filename:
            self.status_var.set("Sanitization completed, but Save As was cancelled. No file was written.")
            return

        output_path = Path(output_filename)

        try:
            if output_path.resolve() == input_path.resolve():
                messagebox.showerror(
                    "Original file protected",
                    "Choose a different output filename. This application will not overwrite the original OPNsense export.",
                )
                self.status_var.set("Save cancelled to protect the original XML.")
                return
        except OSError:
            # resolve() can fail in unusual path situations; normal save handling below will report errors.
            pass

        try:
            tree.write(output_path, encoding="utf-8", xml_declaration=True)
        except Exception as exc:
            messagebox.showerror("Save failed", f"The sanitized XML could not be saved:\n\n{exc}")
            self.status_var.set("Sanitization succeeded, but saving the output file failed.")
            return

        self.last_output_path = output_path
        self.output_var.set(str(output_path))
        self.open_folder_button.config(state="normal")

        summary = (
            f"Complete. Cleared {stats['secret_fields']} secret field(s), "
            f"{stats['credential_usernames']} credential username(s), "
            f"{stats['geoip_urls']} GeoIP URL(s)"
        )
        if self.strip_audit_var.get():
            summary += f", and {stats['audit_usernames']} audit username/IP field(s)"
        summary += ". Fail-safe validation passed."

        self.status_var.set(summary)
        messagebox.showinfo("Sanitization complete", f"Sanitized configuration saved to:\n\n{output_path}")

    def open_output_folder(self):
        if self.last_output_path is None:
            return
        folder = self.last_output_path.parent
        try:
            os.startfile(folder)  # Windows-only, appropriate for this Windows desktop app.
        except Exception as exc:
            messagebox.showerror("Could not open folder", str(exc))


if __name__ == "__main__":
    app = OPNsenseCleanerApp()
    app.mainloop()
