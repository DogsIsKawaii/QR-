const loc = window.__LOC__ || "";
const msgEl = document.getElementById("msg");
const checkinBtn = document.getElementById("checkinBtn");
const loginBtn = document.getElementById("loginBtn");

function setMsg(text) {
  msgEl.textContent = text || "";
}

function showLoginLink() {
  const nextUrl = "/?loc=" + encodeURIComponent(loc);
  loginBtn.href = "/login?next=" + encodeURIComponent(nextUrl);
  loginBtn.style.display = "inline-block";
}

checkinBtn.addEventListener("click", async () => {
  setMsg("처리 중...");
  loginBtn.style.display = "none";

  try {
    const res = await fetch("/api/checkin?loc=" + encodeURIComponent(loc), { method: "POST" });
    let data = {};
    try { data = await res.json(); } catch {}

    if (res.status === 401) {
      setMsg("Discord 로그인 후 시도해주세요.");
      showLoginLink();
      return;
    }

    if (!res.ok) {
      setMsg(data.detail || "오류가 발생했습니다.");
      return;
    }

    setMsg((data.already ? "" : "환영합니다!\n") + (data.message || ""));
  } catch (e) {
    setMsg("네트워크 오류가 발생했습니다. 다시 시도해주세요.");
  }
});
