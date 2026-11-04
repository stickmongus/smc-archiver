# ⚡ SMC Archiver

**SMC (Smart Multi-core Container)**는 Rust 기반의 초고속 멀티코어 압축 프로그램입니다.  
자체 병렬 청크 포맷(`.smc`)뿐만 아니라 표준 `.zip` 생성·해제 및 `.7z`(분할 볼륨 포함) 열기·미리보기·병렬 해제를 단일 실행 파일(`smc.exe`)로 지원합니다.

---

## ✨ 주요 기능 (v1.2.0)

- **🚀 초고속 멀티코어 병렬 압축 & 해제 (`.smc`)**
  - 대용량 파일을 `4 MB` 청크 단위로 분할하여 모든 CPU 코어(`Rayon`)에서 동시에 압축·해제합니다.
  - **Smart Auto 모드**: 청크 엔트로피를 실시간 분석해 `LZ4`(초고속), `Zstandard`(고효율), `Store`(무압축 바이패스) 중 최적 알고리즘을 자동 선택합니다.
  - **Smart Bypass**: 이미 압축된 미디어·아카이브 확장자(`.mp4`, `.jpg`, `.png`, `.zip`, `.7z` 등)는 불필요한 재압축 없이 디스크 I/O 속도로 즉시 패키징합니다.
- **📦 범용 아카이브 호환 (`.smc` / `.zip` / `.7z`)**
  - **열기 · 미리보기 · 더블클릭 즉시 실행 · 병렬 해제**: `.smc`(분할 `.s01`~), `.zip`(Deflate/Deflate64/Zstd/LZMA/XZ/PPMd, AES/ZipCrypto), `.7z`(LZMA/LZMA2/Zstd/LZ4/PPMd/BCJ, AES-256 암호화, 분할 `.7z.001`~) 지원
  - **한글 인코딩 자동 복원**: UTF-8 우선 디코딩 및 구형 압축기의 `CP949(EUC-KR)` 파일명·텍스트 미리보기 자동 복원
  - **표준 `.zip` 생성 지원**: 만들기 탭에서 `.smc` 또는 호환용 `.zip`(ZIP64, AES-256 암호화, 빈 폴더 보존) 선택 가능
- **🛡 보안 및 데이터 무결성**
  - **AES-256-GCM + PBKDF2-HMAC-SHA256 (600,000회)**: 청크 및 인덱스 테이블 암호화 인증 및 메모리 키 캐시(`Drop` 시 volatile zeroize)
  - **무결성 검사 (`🛡 무결성 검사`)**: 디스크 쓰기 없이 모든 청크·암호화 태그·CRC32를 병렬 검증
  - **안전한 경로 검증**: Zip-Slip(`..`), 드라이브 문자, NTFS ADS(`:`) 차단 및 손상 헤더 OOM 방어
- **🖥 편의 기능 (GUI & Windows 탐색기 연동)**
  - 아카이브 내부 이미지·텍스트 즉시 미리보기 및 더블클릭 즉시 실행(종료/재시작 시 오래된 임시 폴더 자동 정리)
  - **알아서 풀기 (`smart_extract_dir`)**: 단일 루트 폴더 중복 중첩(`폴더/폴더`) 방지 및 이름 충돌 시 자동 분리(`폴더 (2)`)
  - 분할 볼륨 압축(`.smc`, `.s01`, `.s02`...) 및 Windows 탐색기 전용 아이콘·우클릭 컨텍스트 메뉴 등록/해제

---

## 📥 다운로드 및 실행

별도 설치 없이 **[Releases](../../releases)** 페이지에서 최신 `smc.exe` 단일 파일을 내려받아 바로 실행할 수 있습니다.

---

## 🛠 소스 빌드 및 테스트

### 요구 사항
- Windows 10 / 11 (x64)
- Rust `1.80+` (`cargo`, MSVC Build Tools)

### 명령어
```powershell
# 유닛 테스트 실행
cargo test

# 최적화 릴리즈 빌드 (target/release/smc.exe 생성)
cargo build --release
```

---

## 📁 프로젝트 구조

```text
├── Cargo.toml              # 패키지 설정 및 의존성
├── build.rs                # 전용 아이콘(.ico) 생성 및 Windows 리소스 임베딩
└── src/
    ├── main.rs             # 엔트리포인트, CLI 인자 처리, 통합 유닛 테스트
    ├── format.rs           # .smc 컨테이너 헤더/인덱스 스펙 및 압축 옵션 정의
    ├── archiver.rs         # 멀티코어 .smc 압축/해제/분할볼륨/무결성 검증 엔진
    ├── external_archive.rs # .zip / .7z 통합 리더·프리뷰·병렬 해제 및 .zip 생성기
    ├── crypto.rs           # AES-256-GCM 암복호화 및 PBKDF2(v1/v2) 키 파생·캐시
    ├── gui.rs              # egui/eframe 기반 네이티브 한국어 GUI
    ├── explorer.rs         # Windows 레지스트리(HKCU) 확장자 아이콘 및 우클릭 메뉴 연동
    └── icon.rs             # 런타임 윈도우 아이콘 렌더러
```
