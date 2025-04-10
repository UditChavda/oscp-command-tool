🧠 OSCP Command Toolbox

A Powerful, Customizable, and Offline-Ready Pentesting Cheat Sheet for OSCP & Beyond

🔍 About the Project

The OSCP Command Toolbox is your all-in-one, browser-based OSCP command reference crafted for aspiring and experienced penetration testers. Whether you're studying for the OSCP exam or need a fast reference during real-world engagements, this sleek web app gives you quick access to categorized, dynamic, and copy-ready commands—with zero dependency on internet or bulky PDFs.
✨ Key Features

    📂 Comprehensive Coverage: Recon, Enumeration, Exploitation, Privilege Escalation (Linux & Windows), Pivoting, Cracking, and more.

    💡 Dynamic Variables: Replace <IP>, <PORT>, <LHOST>, etc. across commands in real time.

    🔎 Smart Search: Instantly find any tool, section, or command description.

    🖱️ One-Click Copy: Copy commands directly to clipboard—no more manual selection.

    🌐 Fully Offline Capable: Host it locally or on GitHub Pages—no external dependencies.

    🧰 JSON-Powered Backend: Easily expand or customize your command sets via toolbox.json.

    🎨 Clean Hacker-Themed UI: Dark mode, responsive design, and OSCP-themed background for immersive focus.

🚀 Live Demo

👉 Use it now – OSCP Command Toolbox
📁 How to Use It Locally

# Clone the repository
git clone https://github.com/uditchavda/oscp-command-tool.git

# Navigate to the folder
cd oscp-command-tool

# Open index.html in any browser

Or just open index.html directly after downloading.
🔧 Customize Commands

You can add/edit tools and commands by editing the toolbox.json file. Structure:

{
  "Section Name": {
    "Tool Name": [
      {
        "title": "Description",
        "command": "command using <IP>, <PORT>, <LHOST>, etc."
      }
    ]
  }
}

💬 Want to Contribute?

Found a cool technique or an OSCP-relevant command that’s missing?
Open a PR or drop it in Issues—let’s build the ultimate toolbox together!
📄 License

This project is licensed under the MIT License.
Use it, fork it, share it freely 🚀
