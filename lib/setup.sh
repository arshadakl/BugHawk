#!/usr/bin/env bash
# lib/setup.sh — OS detection, package manager detection, tool check + auto-install

# ── OS Detection ──────────────────────────────────────────────────────────────
detect_os() {
  if grep -qi microsoft /proc/version 2>/dev/null; then
    OS="wsl"
    return
  fi
  case "$(uname -s)" in
    Linux*)               OS="linux" ;;
    Darwin*)              OS="mac" ;;
    CYGWIN*|MINGW*|MSYS*) OS="windows_bash" ;;
    *)                    OS="unknown" ;;
  esac
}

# ── Package Manager Detection ─────────────────────────────────────────────────
detect_pkg_manager() {
  if   command -v apt-get &>/dev/null; then PKG="apt"
  elif command -v brew    &>/dev/null; then PKG="brew"
  elif command -v pacman  &>/dev/null; then PKG="pacman"
  elif command -v winget  &>/dev/null; then PKG="winget"
  elif command -v choco   &>/dev/null; then PKG="choco"
  else                                      PKG="none"
  fi
}

# ── Go PATH Check ─────────────────────────────────────────────────────────────
check_go_path() {
  local go_bin="$HOME/go/bin"
  if [[ ":$PATH:" != *":$go_bin:"* ]]; then
    export PATH="$PATH:$go_bin"
    # Persist to shell rc file
    local rc_file="$HOME/.bashrc"
    [ "$OS" = "mac" ] && rc_file="$HOME/.zshrc"
    if ! grep -qF "$go_bin" "$rc_file" 2>/dev/null; then
      echo 'export PATH="$PATH:$HOME/go/bin"' >> "$rc_file"
      log_info "Added \$HOME/go/bin to PATH in $rc_file"
    fi
  fi
}

# ── Install via Package Manager ───────────────────────────────────────────────
install_via_pkg() {
  local pkg="$1"
  case "$PKG" in
    apt)    sudo apt-get install -y "$pkg" &>/dev/null ;;
    brew)   brew install "$pkg" &>/dev/null ;;
    pacman) sudo pacman -S --noconfirm "$pkg" &>/dev/null ;;
    winget) winget install -e --id "$pkg" --silent &>/dev/null ;;
    choco)  choco install "$pkg" -y &>/dev/null ;;
    *)      return 1 ;;
  esac
}

# ── Install Go Tool ───────────────────────────────────────────────────────────
install_go_tool() {
  local import_path="$1"
  if ! command -v go &>/dev/null; then
    log_warn "Go not installed — cannot install $import_path"
    return 1
  fi
  go install -v "$import_path" &>/dev/null
}

# ── Install trufflehog (curl script + binary fallback) ────────────────────────
install_trufflehog() {
  # Try curl install script first
  if curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
       | sh -s -- -b "$HOME/.local/bin" &>/dev/null; then
    export PATH="$PATH:$HOME/.local/bin"
    return 0
  fi
  # Fallback: GitHub releases binary
  local os_tag="linux_amd64"
  [ "$OS" = "mac" ] && os_tag="darwin_amd64"
  local url
  url=$(curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest \
        | grep "browser_download_url" | grep "$os_tag.tar.gz" | head -1 \
        | cut -d'"' -f4)
  if [ -n "$url" ]; then
    curl -sSL "$url" | tar -xz -C /tmp trufflehog 2>/dev/null
    mv /tmp/trufflehog "$HOME/.local/bin/trufflehog" 2>/dev/null
    chmod +x "$HOME/.local/bin/trufflehog"
    export PATH="$PATH:$HOME/.local/bin"
  fi
}

# ── Install gitleaks (GitHub releases binary) ─────────────────────────────────
install_gitleaks() {
  # Detect OS+arch — gitleaks uses linux_x64/linux_arm64/darwin_arm64/windows_x64
  local arch
  arch=$(uname -m)
  local os_tag
  case "$OS" in
    mac)
      [ "$arch" = "arm64" ] && os_tag="darwin_arm64" || os_tag="darwin_x64"
      ;;
    windows_bash)
      os_tag="windows_x64"
      ;;
    *)  # linux, wsl
      [ "$arch" = "aarch64" ] && os_tag="linux_arm64" || os_tag="linux_x64"
      ;;
  esac
  local url
  url=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
        | grep "browser_download_url" | grep "${os_tag}.tar.gz" | head -1 \
        | cut -d'"' -f4)
  if [ -n "$url" ]; then
    mkdir -p "$HOME/.local/bin"
    curl -sSL "$url" | tar -xz -C /tmp gitleaks 2>/dev/null
    mv /tmp/gitleaks "$HOME/.local/bin/gitleaks" 2>/dev/null
    chmod +x "$HOME/.local/bin/gitleaks"
    export PATH="$PATH:$HOME/.local/bin"
  fi
}

# ── Per-Tool Install Logic ────────────────────────────────────────────────────
install_tool() {
  local tool="$1"
  log_info "Installing: $tool"
  case "$tool" in
    go)
      case "$PKG" in
        apt)    sudo apt-get install -y golang &>/dev/null ;;
        brew)   brew install go &>/dev/null ;;
        pacman) sudo pacman -S --noconfirm go &>/dev/null ;;
        winget) winget install -e --id GoLang.Go --silent &>/dev/null ;;
        choco)  choco install golang -y &>/dev/null ;;
      esac ;;
    python3)
      case "$PKG" in
        apt)    sudo apt-get install -y python3 python3-pip &>/dev/null ;;
        brew)   brew install python &>/dev/null ;;
        winget) winget install -e --id Python.Python.3 --silent &>/dev/null ;;
      esac ;;
    jq)          install_via_pkg jq ;;
    curl)        install_via_pkg curl ;;
    nmap)
      case "$PKG" in
        apt)    sudo apt-get install -y nmap &>/dev/null ;;
        brew)   brew install nmap &>/dev/null ;;
        pacman) sudo pacman -S --noconfirm nmap &>/dev/null ;;
        winget) winget install -e --id Insecure.Nmap --silent &>/dev/null ;;
        choco)  choco install nmap -y &>/dev/null ;;
      esac ;;
    whois)       install_via_pkg whois ;;
    sqlmap)      pip3 install sqlmap --break-system-packages &>/dev/null ;;
    paramspider)
      # Try PyPI first; fall back to GitHub source (Python 3.13 compat)
      pip3 install paramspider --break-system-packages &>/dev/null || \
      pip3 install "git+https://github.com/devanshbatham/paramspider" \
        --break-system-packages &>/dev/null || true
      ;;
    subfinder)   install_go_tool "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" ;;
    httpx)       install_go_tool "github.com/projectdiscovery/httpx/cmd/httpx@latest" ;;
    nuclei)
      install_go_tool "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
      # Update templates after install to avoid mid-scan download
      command -v nuclei &>/dev/null && nuclei -update-templates -silent &>/dev/null || true ;;
    dalfox)      install_go_tool "github.com/hahwul/dalfox/v2@latest" ;;
    ffuf)        install_go_tool "github.com/ffuf/ffuf/v2@latest" ;;
    gf)
      install_go_tool "github.com/tomnomnom/gf@latest"
      # Clone pattern files required separately
      if [ ! -d "$HOME/.gf" ]; then
        git clone https://github.com/1ndianl33t/Gf-Patterns "$HOME/.gf" &>/dev/null \
          && log_info "gf patterns installed to ~/.gf"
      fi ;;
    waybackurls) install_go_tool "github.com/tomnomnom/waybackurls@latest" ;;
    anew)        install_go_tool "github.com/tomnomnom/anew@latest" ;;
    trufflehog)  install_trufflehog ;;
    gitleaks)    install_gitleaks ;;
    subzy)       install_go_tool "github.com/PentestPad/subzy@latest" ;;
    testssl)
      if [ ! -d "/opt/testssl" ]; then
        git clone --depth 1 https://github.com/drwetter/testssl.sh /opt/testssl &>/dev/null \
          && chmod +x /opt/testssl/testssl.sh \
          || log_warn "testssl clone failed — SSL check will be skipped"
      fi ;;
    interactsh-client)
      install_go_tool "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest" ;;
    *)           log_warn "No install handler for: $tool"; return 1 ;;
  esac
}

# ── Get Tool Version String ───────────────────────────────────────────────────
get_version() {
  local tool="$1"
  case "$tool" in
    go)          go version 2>/dev/null | awk '{print $3}' ;;
    python3)     python3 --version 2>/dev/null | awk '{print $2}' ;;
    jq)          jq --version 2>/dev/null ;;
    curl)        curl --version 2>/dev/null | head -1 | awk '{print $2}' ;;
    subfinder)   subfinder -version 2>&1 | head -1 ;;
    httpx)       "$HOME/go/bin/httpx" -version 2>&1 | head -1 ;;
    nuclei)      nuclei -version 2>&1 | head -1 ;;
    nmap)        nmap --version 2>/dev/null | head -1 | awk '{print $3}' ;;
    sqlmap)      sqlmap --version 2>/dev/null | head -1 ;;
    dalfox)      dalfox version 2>/dev/null | head -1 ;;
    ffuf)        ffuf -V 2>/dev/null ;;
    gf)          echo "installed" ;;
    waybackurls) echo "installed" ;;
    anew)        echo "installed" ;;
    paramspider) paramspider --help 2>&1 | head -1 | cut -c1-20 || echo "installed" ;;
    trufflehog)  trufflehog --version 2>/dev/null | head -1 ;;
    gitleaks)    gitleaks version 2>/dev/null ;;
    whois)       whois --version 2>/dev/null | head -1 || echo "installed" ;;
    subzy)       "$HOME/go/bin/subzy" version 2>/dev/null | head -1 || echo "installed" ;;
    testssl)     [ -x /opt/testssl/testssl.sh ] && /opt/testssl/testssl.sh --version 2>/dev/null | head -1 || echo "not found" ;;
    interactsh-client) "$HOME/go/bin/interactsh-client" -version 2>/dev/null | head -1 || echo "installed" ;;
    *)           echo "unknown" ;;
  esac
}

# ── Main Setup Runner ─────────────────────────────────────────────────────────
run_setup() {
  detect_os
  detect_pkg_manager
  check_go_path

  log_info "OS: $OS | Package manager: $PKG"

  if [ "$OS" = "windows_bash" ]; then
    log_warn "Windows Git Bash detected — some tools may not auto-install."
    log_warn "Recommend WSL2 for full support."
  fi

  local tools=(
    go python3 jq curl
    subfinder httpx nuclei nmap sqlmap dalfox ffuf
    gf waybackurls anew paramspider
    trufflehog gitleaks whois
    subzy testssl interactsh-client
  )

  print_tool_table_header

  local skipped_tools=()
  for tool in "${tools[@]}"; do
    local binary="$tool"
    # httpx binary lives in go/bin to avoid Python httpx conflict
    [ "$tool" = "httpx" ]              && binary="$HOME/go/bin/httpx"
    [ "$tool" = "subzy" ]              && binary="$HOME/go/bin/subzy"
    [ "$tool" = "interactsh-client" ]  && binary="$HOME/go/bin/interactsh-client"
    [ "$tool" = "testssl" ]            && binary="/opt/testssl/testssl.sh"

    if command -v "$binary" &>/dev/null 2>&1 || [ -x "$binary" ]; then
      local ver
      ver=$(get_version "$tool" 2>/dev/null | head -c 20 || echo "ok")
      print_tool_row "$tool" "✓" "$ver"
    else
      if install_tool "$tool" 2>/dev/null; then
        if command -v "$binary" &>/dev/null 2>&1 || [ -x "$binary" ]; then
          print_tool_row "$tool" "✓" "installed"
        else
          print_tool_row "$tool" "✗" "install failed"
          skipped_tools+=("$tool")
        fi
      else
        print_tool_row "$tool" "✗" "skipped"
        skipped_tools+=("$tool")
        local ts
        ts=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$ts] SETUP: failed to install $tool" >> "${OUTDIR:-/tmp}/errors.log"
      fi
    fi
  done

  echo ""
  if [ ${#skipped_tools[@]} -gt 0 ]; then
    log_warn "Skipped tools: ${skipped_tools[*]}"
    log_warn "Results may be incomplete for those scan types."
  else
    log_success "All tools ready."
  fi
}
