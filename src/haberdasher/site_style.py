"""The shared stylesheet, the eight brand themes, the script, and the inline icons of the pages."""

from __future__ import annotations

from dataclasses import dataclass

# Exact jsDelivr paths and the SHA-384 SRI digests of their served bytes.
STYLES = {
    "@digicreon/mucss@1.4.9/dist/mu.orange.css": "sha384-RWjv5U5P9qrGA/d0BeUQffNMBO0uWgdz6pOWxLoZkWXfLENNQJXKt7dr7g8Khb1C",
    "@digicreon/mucss@1.4.9/dist/mu.red.css": "sha384-T8B/jJxtffli4kRoMnNnM9r6sTPwB//d2IyD27RoJ8s/GKBtbB9NzOj326GthqyJ",
    "@digicreon/mucss@1.4.9/dist/mu.azure.css": "sha384-YjTpibR/F7FR3aIGG2zomRYyj5iVUC8YZMDXyEpUjoYzvnA+xRlC57sqqdhse4si",
    "@fontsource-variable/ubuntu-sans@5.3.0/index.css": "sha384-eEpXUNlfeYRFiOQPH+UJxPXv4kEihRq0PEwCjWBOn1UAU7NKTkeBnSwQp+dKUlpR",
    "@fontsource-variable/ubuntu-sans-mono@5.3.0/index.css": "sha384-pTWkqX4PDBAjEsqmipctvyqTB61N5+KOkZwwV0qTfb3y/aiWOgzdQ7nTpDNMFt8R",
    "@fontsource/red-hat-display@5.3.0/latin-700.css": "sha384-+5KZTNIZygIXY/HKL9IMr8E8KXyHWLcLXq20QErBF6HFBp1rCUKoYYwTRMus5J2n",
    "@fontsource/red-hat-text@5.3.0/latin-400.css": "sha384-tp/ewtWBoD+TTx4nbbBgWqUxB7pAGpx2dDIWhUB7RAAZQfVsOZE9BJQ/+2ocys8v",
    "@fontsource/red-hat-text@5.3.0/latin-500.css": "sha384-7/1FKLV8SzgEjbxZi00WTSdfok5BobgjT41ugDfDlruA4nOC5bB9xqUuR4j98Fkx",
    "@fontsource/red-hat-mono@5.3.0/latin-400.css": "sha384-JkJs+eQFcNI0h1qK4qS3lnYHOk+J2RgEmq70OMHlv+hhn3cCXKqy8OEVl2f2ORBO",
    "@fontsource/red-hat-mono@5.3.0/latin-700.css": "sha384-Ba4KHP6/Y0CbDXLCvoqqLxPrIdxiLxr46DD/7T2CenXpn8hB9lAiQFXVaiVTAX7G",
    "@fontsource/dejavu-sans@5.3.0/latin-400.css": "sha384-CidZsVfobFW5xiOFOpkje5OcSC831DXEm2waw/GLoh389633DozcNZXOS9Wrsw6A",
    "@fontsource/dejavu-sans@5.3.0/latin-700.css": "sha384-rsmR51NRYSIjadzC8EHbB+voaPjqUo3l8aEaLEIrwx4aGqJ3nG4VZQaPdOtXRT/w",
    "@fontsource/dejavu-mono@5.3.0/latin-400.css": "sha384-pjcCZfsr/LBA7sjODrHe5KCgsGOgP4RKZBSMRDXaj78mDsMNEekkPUIYY/cTepVV",
    "@fontsource/dejavu-mono@5.3.0/latin-700.css": "sha384-SS2tWoQnShmnRcQoAmoqbtODdw8xSuH+1OfGEzeuZkZYPfWG2F6HLMtW+nn4i0Fj",
    "@fontsource/arimo@5.3.0/latin-400.css": "sha384-gJJLMWRZpfhRVxi/dtdsLcoS1CXoa7utm4A/MBIeyAfWjf16JS3NiyWyk/BDlNo2",
    "@fontsource/arimo@5.3.0/latin-700.css": "sha384-ArTaF4Kcm2BVTsfPcif0tQ6asJ/n4v0p8U0OBplWot4ppH4FxJ5jyvMmeMHrJ5yQ",
    "@fontsource/cousine@5.3.0/latin-400.css": "sha384-crHswLQRdfcWj8DIWHiUdhLLDKghskAjKW+Iy1cQ6O1C9x52Ek5WaFhC7VLUvOJ7",
    "@fontsource/cousine@5.3.0/latin-700.css": "sha384-tG8CFTdtq5ewtuFenkTbbpYrkh/J3DyeAY/aVlbUY6lJKjMIMcOVdCRrn+YjmHF6",
    "@fontsource/comfortaa@5.3.0/latin-700.css": "sha384-ppGjQufwxh9iqxwY6fxMVm3kJTgfhnT0vwqXf842xWOZ3EzbAgRbJnebfXjbjZOR",
    "@fontsource-variable/inter@5.3.0/index.css": "sha384-ZTIcl2CmY0wyM9ANOhomBco7rEUIlWztf6lGcLKCocKUrIgGCsfisuZyE+hadW8K",
    "@fontsource/jetbrains-mono@5.3.0/latin-400.css": "sha384-rDtx9NW9VQWFrGIe8txtelRagz09ojKYLeaff45i3hEq7ofdZdkNlxVO8XCT5yPu",
    "@fontsource/jetbrains-mono@5.3.0/latin-700.css": "sha384-YN3ECHWok15EKo4719ITyHrjG2kMj10l78t/s9dJ/veNjwIgebpaLpWJ0g/eHN6T",
}

# simple-icons 16.37.0 paths (CC0), inlined so that they take currentColor. Arch drops its
# trademark glyph.
MARKS = {
    "apt": "M17.61.455a3.41 3.41 0 0 0-3.41 3.41 3.41 3.41 0 0 0 3.41 3.41 3.41 3.41 0 0 0 3.41-3.41 3.41 3.41 0 0 0-3.41-3.41zM12.92.8C8.923.777 5.137 2.941 3.148 6.451a4.5 4.5 0 0 1 .26-.007 4.92 4.92 0 0 1 2.585.737A8.316 8.316 0 0 1 12.688 3.6 4.944 4.944 0 0 1 13.723.834 11.008 11.008 0 0 0 12.92.8zm9.226 4.994a4.915 4.915 0 0 1-1.918 2.246 8.36 8.36 0 0 1-.273 8.303 4.89 4.89 0 0 1 1.632 2.54 11.156 11.156 0 0 0 .559-13.089zM3.41 7.932A3.41 3.41 0 0 0 0 11.342a3.41 3.41 0 0 0 3.41 3.409 3.41 3.41 0 0 0 3.41-3.41 3.41 3.41 0 0 0-3.41-3.41zm2.027 7.866a4.908 4.908 0 0 1-2.915.358 11.1 11.1 0 0 0 7.991 6.698 11.234 11.234 0 0 0 2.422.249 4.879 4.879 0 0 1-.999-2.85 8.484 8.484 0 0 1-.836-.136 8.304 8.304 0 0 1-5.663-4.32zm11.405.928a3.41 3.41 0 0 0-3.41 3.41 3.41 3.41 0 0 0 3.41 3.41 3.41 3.41 0 0 0 3.41-3.41 3.41 3.41 0 0 0-3.41-3.41z",
    "rpm": "M16.009 13.386c1.577 0 3.86-.326 3.86-2.202a1.765 1.765 0 0 0-.04-.431l-.94-4.08c-.216-.898-.406-1.305-1.982-2.093-1.223-.625-3.888-1.658-4.676-1.658-.733 0-.947.946-1.822.946-.842 0-1.467-.706-2.255-.706-.757 0-1.25.515-1.63 1.576 0 0-1.06 2.99-1.197 3.424a.81.81 0 0 0-.028.245c0 1.162 4.577 4.974 10.71 4.974m4.101-1.435c.218 1.032.218 1.14.218 1.277 0 1.765-1.984 2.745-4.593 2.745-5.895.004-11.06-3.451-11.06-5.734a2.326 2.326 0 0 1 .19-.925C2.746 9.415 0 9.794 0 12.217c0 3.969 9.405 8.861 16.851 8.861 5.71 0 7.149-2.582 7.149-4.62 0-1.605-1.387-3.425-3.887-4.512",
    "arch": "M11.39.605C10.376 3.092 9.764 4.72 8.635 7.132c.693.734 1.543 1.589 2.923 2.554-1.484-.61-2.496-1.224-3.252-1.86C6.86 10.842 4.596 15.138 0 23.395c3.612-2.085 6.412-3.37 9.021-3.862a6.61 6.61 0 01-.171-1.547l.003-.115c.058-2.315 1.261-4.095 2.687-3.973 1.426.12 2.534 2.096 2.478 4.409a6.52 6.52 0 01-.146 1.243c2.58.505 5.352 1.787 8.914 3.844-.702-1.293-1.33-2.459-1.929-3.57-.943-.73-1.926-1.682-3.933-2.713 1.38.359 2.367.772 3.137 1.234-6.09-11.334-6.582-12.84-8.67-17.74z",
    "apk": "M5.998 1.607L0 12l5.998 10.393h12.004L24 12 18.002 1.607H5.998zM9.965 7.12L12.66 9.9l1.598 1.595.002-.002 2.41 2.363c-.2.14-.386.252-.563.344a3.756 3.756 0 01-.496.217 2.702 2.702 0 01-.425.111c-.131.023-.25.034-.358.034-.13 0-.242-.014-.338-.034a1.317 1.317 0 01-.24-.072.95.95 0 01-.2-.113l-1.062-1.092-3.039-3.041-1.1 1.053-3.07 3.072a.974.974 0 01-.2.111 1.274 1.274 0 01-.237.073c-.096.02-.209.033-.338.033-.108 0-.227-.009-.358-.031a2.7 2.7 0 01-.425-.114 3.748 3.748 0 01-.496-.217 5.228 5.228 0 01-.563-.343l6.803-6.727zm4.72.785l4.579 4.598 1.382 1.353a5.24 5.24 0 01-.564.344 3.73 3.73 0 01-.494.217 2.697 2.697 0 01-.426.111c-.13.023-.251.034-.36.034-.129 0-.241-.014-.337-.034a1.285 1.285 0 01-.385-.146c-.033-.02-.05-.036-.053-.04l-1.232-1.218-2.111-2.111-.334.334L12.79 9.8l1.896-1.897zm-5.966 4.12v2.529a2.128 2.128 0 01-.356-.035 2.765 2.765 0 01-.422-.116 3.708 3.708 0 01-.488-.214 5.217 5.217 0 01-.555-.34l1.82-1.825Z",
    "flatpak": "M12 0c-.556 0-1.111.144-1.61.432l-7.603 4.39a3.217 3.217 0 0 0-1.61 2.788v8.78c0 1.151.612 2.212 1.61 2.788l7.603 4.39a3.217 3.217 0 0 0 3.22 0l7.603-4.39a3.217 3.217 0 0 0 1.61-2.788V7.61a3.217 3.217 0 0 0-1.61-2.788L13.61.432A3.218 3.218 0 0 0 12 0Zm0 2.358c.15 0 .299.039.431.115l7.604 4.39c.132.077.24.187.315.316L12 12v9.642a.863.863 0 0 1-.431-.116l-7.604-4.39a.866.866 0 0 1-.431-.746V7.61c0-.153.041-.302.116-.43L12 12Z",
    "brew": "M7.938 0a.214.214 0 0 0-.206.156c-.316 1.104.179 2.15.838 2.935.153.181.313.347.476.501a2.039 2.039 0 0 0-.665.02c-1.184.233-2.193.985-2.74 2.532a3.893 3.893 0 0 0-.2 1.466 1.565 1.565 0 0 0-1.156 1.504 1.59 1.59 0 0 0 1.227 1.541l.026 12.046c0 .195.1.377.264.482a.214.214 0 0 0 .008.005c.537.31 2.047.812 5.21.812 3.238 0 4.7-.678 5.181-1.04a.214.214 0 0 0 .008-.007.571.571 0 0 0 .206-.439c.002-.344.002-1.136.002-1.604a.143.143 0 0 1 .147-.144c.397.006.869.006 1.318.005a1.826 1.826 0 0 0 1.832-1.825v-5.804a1.826 1.826 0 0 0-1.825-1.826H16.56a.14.14 0 0 1-.143-.144V10.6h.007v-.001a1.573 1.573 0 0 0 1.356-1.556c0-.816-.627-1.489-1.424-1.563-.025-1.438-.437-2.126-.736-2.58a.214.214 0 0 0-.005-.007c-.364-.51-1.193-1.282-2.275-1.316-.503-.016-.842.124-1.125.254-.217.1-.42.177-.67.22.002-1.286.945-1.981.945-1.981a.214.214 0 0 0 .05-.298s-.087-.122-.21-.26c-.121-.136-.269-.294-.47-.378a.214.214 0 0 0-.079-.017.214.214 0 0 0-.145.055 4.308 4.308 0 0 0-.875 1.101 3.42 3.42 0 0 0-.133.273 3.497 3.497 0 0 0-.381-.846C9.794.978 9.063.436 8.017.016A.214.214 0 0 0 7.939 0zm.156.524c.85.378 1.43.83 1.79 1.403.274.438.426.962.484 1.584a3.07 3.07 0 0 0-.012.462 6.897 6.897 0 0 1-.168-.052 5.487 5.487 0 0 1-1.29-1.106c-.551-.657-.935-1.46-.804-2.291zM11.8 1.618c.07.054.141.101.212.18.034.039.032.04.058.073-.332.308-1.07 1.144-.952 2.453a.214.214 0 0 0 .222.195c.469-.017.782-.172 1.056-.299.273-.126.508-.228.931-.214.875.027 1.639.715 1.939 1.134.295.449.65 1 .663 2.36a1.66 1.66 0 0 0-.41.142 1.938 1.938 0 0 0-1.77-1.16 1.94 1.94 0 0 0-1.87 1.448 1.783 1.783 0 0 0-1.356-.64c-.484 0-.91.205-1.233.517a1.873 1.873 0 0 0-1.85-1.625c-.649 0-1.218.335-1.552.84a3.1 3.1 0 0 1 .157-.735c.51-1.437 1.355-2.045 2.42-2.254.367-.073.664-.011.99.095.325.106.671.262 1.094.342a.214.214 0 0 0 .252-.245c-.112-.67.073-1.266.336-1.744a3.71 3.71 0 0 1 .663-.863zM7.44 6.611a1.442 1.442 0 0 1 1.363 1.925.214.214 0 0 0 .168.283h.005a.214.214 0 0 0 .238-.146 1.373 1.373 0 0 1 2.613-.01.214.214 0 0 0 .417-.09 1.509 1.509 0 0 1 1.504-1.664c.678 0 1.249.445 1.442 1.056a.214.214 0 0 0 .259.143l.15-.04a.214.214 0 0 0 .051-.02 1.139 1.139 0 0 1 1.702.995 1.14 1.14 0 0 1-.985 1.131.214.214 0 0 0-.001 0 2.215 2.215 0 0 0-.485.126 10.65 10.65 0 0 1-1.176.365.214.214 0 0 0-.162.186 1.276 1.276 0 0 1-.146.478 2.07 2.07 0 0 0-.239 1.111l.001.151a.438.438 0 0 1-.16.36.665.665 0 0 1-.43.14.586.586 0 0 1-.588-.59.803.803 0 0 0-.38-.681.214.214 0 0 0-.002-.002c-.24-.145-.43-.37-.532-.636a.214.214 0 0 0-.207-.138 19.469 19.469 0 0 1-5.37-.6l-.003-.002a9.007 9.007 0 0 0-.838-.194h.003a1.16 1.16 0 0 1-.937-1.134c0-.619.488-1.118 1.101-1.14a.214.214 0 0 0 .204-.176 1.443 1.443 0 0 1 1.42-1.187zm8.549 4.106v.455c0 .314.259.573.572.573h1.329a1.397 1.397 0 0 1 1.397 1.397v5.804a1.396 1.396 0 0 1-1.402 1.396.214.214 0 0 0-.002 0c-.448.002-.918 0-1.31-.005a.573.573 0 0 0-.584.573c0 .468 0 1.262-.002 1.603a.214.214 0 0 0 0 .001c0 .042-.019.08-.05.107-.346.26-1.75.95-4.915.95-3.107 0-4.587-.52-4.99-.752a.143.143 0 0 1-.065-.118l-.025-11.955c.145.033.288.07.431.11a.214.214 0 0 0 .003 0c.115.031.246.064.383.097v10.37c0 .129.069.247.18.31.453.217 1.767.732 4.071.732 2.32 0 3.595-.626 4.022-.884a.357.357 0 0 0 .164-.3l.001-10.21c.267-.075.531-.158.792-.254zm-7.99.894a.493.493 0 0 1 .494.493v8.578a.493.493 0 0 1-.493.493.493.493 0 0 1-.494-.493v-8.578A.493.493 0 0 1 8 11.611zm8.652 1.14a.663.663 0 0 0-.662.662v5.208a.663.663 0 0 0 .662.662h1.14a.663.663 0 0 0 .662-.662v-5.209a.663.663 0 0 0-.662-.662zm0 .428h1.14a.233.233 0 0 1 .233.233v5.21a.233.233 0 0 1-.233.232h-1.14a.233.233 0 0 1-.233-.233v-5.209a.233.233 0 0 1 .233-.233z",
    "nix": "M7.352 1.592l-1.364.002L5.32 2.75l1.557 2.713-3.137-.008-1.32 2.34H14.11l-1.353-2.332-3.192-.006-2.214-3.865zm6.175 0l-2.687.025 5.846 10.127 1.341-2.34-1.59-2.765 2.24-3.85-.683-1.182h-1.336l-1.57 2.705-1.56-2.72zm6.887 4.195l-5.846 10.125 2.696-.008 1.601-2.76 4.453.016.682-1.183-.666-1.157-3.13-.008L21.778 8.1l-1.365-2.313zM9.432 8.086l-2.696.008-1.601 2.76-4.453-.016L0 12.02l.666 1.157 3.13.008-1.575 2.71 1.365 2.315L9.432 8.086zM7.33 12.25l-.006.01-.002-.004-1.342 2.34 1.59 2.765-2.24 3.85.684 1.182H7.35l.004-.006h.001l1.567-2.698 1.558 2.72 2.688-.026-.004-.006h.01L7.33 12.25zm2.55 3.93l1.354 2.332 3.192.006 2.215 3.865 1.363-.002.668-1.156-1.557-2.713 3.137.008 1.32-2.34H9.881Z",
}


# simple-icons has no Scoop mark, so this is a drawn ice cream bowl after the Scoop logo.
SCOOP_MARK = "M7.5 6a4.5 4.5 0 1 0 9 0a4.5 4.5 0 1 0-9 0zM2.5 8.5a4 4 0 1 0 8 0a4 4 0 1 0-8 0zM13.5 8.5a4 4 0 1 0 8 0a4 4 0 1 0-8 0zM1.5 13.5h21a10.5 5.5 0 0 1-21 0zM8.5 20h7a1 1 0 0 1 1 1v1h-9v-1a1 1 0 0 1 1-1z"


@dataclass(frozen=True)
class Theme:
    """A brand theme: the µCSS colour build, the fonts, the "Works with" logos, and the CSS.

    `logo` holds the fill of `logo.svg` on a light and on a dark background.
    """

    label: str
    short: str
    icon: str
    mu: str
    fonts: tuple[str, ...]
    works: tuple[tuple[str | None, str], ...]
    favicon: str
    logo: tuple[str, str]
    css: str

    @property
    def styles(self) -> tuple[str, ...]:
        return (self.mu, *self.fonts)


def dark(block: str) -> str:
    """Emit a dark block for both the system preference and an explicit data-theme."""
    return (
        f"@media (prefers-color-scheme:dark){{{block.replace('SEL', ':root:not([data-theme=light])')}}}\n"
        f"{block.replace('SEL', '[data-theme=dark]')}\n"
    )


THEMES: dict[str, Theme] = {
    "apt": Theme(
        label="APT",
        short="APT",
        icon=MARKS["apt"],
        mu="@digicreon/mucss@1.4.9/dist/mu.orange.css",
        fonts=(
            "@fontsource-variable/ubuntu-sans@5.3.0/index.css",
            "@fontsource-variable/ubuntu-sans-mono@5.3.0/index.css",
        ),
        works=(
            ("ubuntu", "Ubuntu"),
            ("debian", "Debian"),
        ),
        favicon="#E95420",
        logo=("#E95420", "#E95420"),
        css="""
body{--hd-font-body:"Ubuntu Sans Variable",Ubuntu,system-ui,sans-serif;--hd-font-display:var(--hd-font-body);--hd-font-mono:"Ubuntu Sans Mono Variable","Ubuntu Mono",ui-monospace,monospace;
--hd-h-weight:300;--hd-h1-weight:200;--hd-h2-weight:400;--hd-h3-weight:500;--hd-h4-weight:500;--hd-radius:.125rem;--hd-btn-radius:.125rem;--hd-pill:.125rem;--hd-step-radius:50%;
--hd-bg:#fff;--hd-fg:#111;--hd-muted:#5d5d5d;--hd-surface:#f7f7f7;--hd-border:#d9d9d9;--hd-link:#0066cc;--hd-focus:#2e96ff;--hd-accent:#E95420;--hd-h2-color:#77216F;
--hd-bar-bg:#2C001E;--hd-bar-fg:#fff;--hd-bar-hover:rgba(255,255,255,.1);--hd-bar-current-bg:#E95420;--hd-bar-current-fg:#111;
--hd-hero-bg:#2C001E;--hd-hero-fg:#fff;--hd-hero-muted:#d9ccd4;--hd-hero-mark:#fff;--hd-hero-rule:#E95420;
--hd-code-bg:#300A24;--hd-code-fg:#fff;--hd-code-border:#300A24;--hd-code-btn-bg:transparent;--hd-code-btn-fg:#F99B78;--hd-code-btn-border:#E95420;--hd-code-btn-hover:rgba(233,84,32,.18);--hd-tag-fg:#F99B78;--hd-tag-bg:rgba(255,255,255,.08);
--hd-btn-bg:#E95420;--hd-btn-fg:#111;--hd-btn-hover:#f29a7e;--hd-step-bg:#E95420;--hd-step-fg:#111;--hd-fp-tail:#C34113;
--hd-tab-active-bg:#fff;--hd-tab-active-fg:#111}
.hero-card{border:0;border-top:3px solid var(--hd-accent);border-radius:0}
.bar{border-top:.375rem solid var(--hd-accent)}
.masthead::before{content:"";position:absolute;inset:0;background:linear-gradient(112deg,transparent 58%,#E95420 58%,#E95420 60.5%,transparent 60.5%,transparent 70%,#3a0a2c 70%);opacity:1}
.masthead h1{letter-spacing:-.01em}
h2{color:var(--hd-h2-color)}
@media (max-width:900px){.masthead::before{display:none}}
.tablist a{border-bottom-width:3px}
.pkg div{border-top:3px solid var(--hd-accent)}
.steps>li:not(:last-child)::after{background:var(--hd-accent);opacity:.35}
"""
        + dark(
            """SEL body{--hd-bg:#262626;--hd-fg:#fff;--hd-muted:#bcbcbc;--hd-surface:#202020;--hd-border:#404040;--hd-link:#7fb8ff;--hd-h2-color:#fff;--hd-guide:#6e6e6e;--hd-code-bg:#1a0613;--hd-code-border:#3a1a30;--hd-btn-hover:#f29a7e;--hd-fp-tail:#F99B78;--hd-tab-active-bg:#333;--hd-tab-active-fg:#fff}"""
        ),
    ),
    "rpm": Theme(
        label="RPM",
        short="RPM",
        icon=MARKS["rpm"],
        mu="@digicreon/mucss@1.4.9/dist/mu.red.css",
        fonts=(
            "@fontsource/red-hat-display@5.3.0/latin-700.css",
            "@fontsource/red-hat-text@5.3.0/latin-400.css",
            "@fontsource/red-hat-text@5.3.0/latin-500.css",
            "@fontsource/red-hat-mono@5.3.0/latin-400.css",
            "@fontsource/red-hat-mono@5.3.0/latin-700.css",
        ),
        works=(
            ("redhat", "Red Hat"),
            ("fedora", "Fedora"),
            ("opensuse", "openSUSE"),
            ("suse", "SUSE"),
        ),
        favicon="#EE0000",
        logo=("#EE0000", "#EE0000"),
        css="""
body{--hd-font-body:"Red Hat Text",system-ui,sans-serif;--hd-font-display:"Red Hat Display",var(--hd-font-body);--hd-font-mono:"Red Hat Mono",ui-monospace,monospace;
--hd-h-weight:700;--hd-radius:0;--hd-btn-radius:0;--hd-pill:0;--hd-step-radius:0;
--hd-bg:#fff;--hd-fg:#151515;--hd-muted:#4d4d4d;--hd-surface:#f2f2f2;--hd-border:#c7c7c7;--hd-link:#0066cc;--hd-focus:#0066cc;--hd-accent:#ee0000;
--hd-bar-bg:#151515;--hd-bar-fg:#fff;--hd-bar-hover:rgba(255,255,255,.1);--hd-bar-current-bg:transparent;--hd-bar-current-fg:#fff;--hd-bar-current-rule:3px;--hd-bar-rule:1px solid #383838;
--hd-hero-bg:#151515;--hd-hero-fg:#fff;--hd-hero-muted:#c7c7c7;--hd-hero-mark:#ee0000;--hd-hero-rule:#ee0000;
--hd-code-bg:#151515;--hd-code-fg:#fff;--hd-code-border:#151515;--hd-code-btn-bg:#ee0000;--hd-code-btn-fg:#fff;--hd-code-btn-border:#ee0000;--hd-code-btn-hover:#a60000;--hd-tag-fg:#c7c7c7;--hd-tag-bg:#383838;
--hd-btn-bg:#ee0000;--hd-btn-fg:#fff;--hd-btn-hover:#a60000;--hd-step-bg:#ee0000;--hd-step-fg:#fff;--hd-fp-tail:#a60000;
--hd-tab-active-bg:transparent;--hd-tab-active-fg:#151515}
.masthead{border-bottom:4px solid var(--hd-accent)}
.masthead h1{letter-spacing:-.02em}
.hero-card{border-top:3px solid var(--hd-accent)}
.foot{background:#151515;color:#c7c7c7;border-top:0}.foot a{color:#fff}
.tablist a{border-bottom-width:3px}
.pkg div{border-top:3px solid var(--hd-accent)}
"""
        + dark(
            """SEL body{--hd-bg:#1f1f1f;--hd-fg:#fff;--hd-muted:#c7c7c7;--hd-surface:#151515;--hd-border:#383838;--hd-guide:#707070;--hd-card-bg:#1f1f1f;--hd-link:#92c5f9;--hd-focus:#92c5f9;--hd-code-bg:#000;--hd-code-border:#383838;--hd-fp-tail:#ff5c5c;--hd-tab-active-fg:#fff;--hd-tag-bg:#484848}"""
        ),
    ),
    "arch": Theme(
        label="Arch Linux",
        short="Arch",
        icon=MARKS["arch"],
        mu="@digicreon/mucss@1.4.9/dist/mu.azure.css",
        fonts=(
            "@fontsource/dejavu-sans@5.3.0/latin-400.css",
            "@fontsource/dejavu-sans@5.3.0/latin-700.css",
            "@fontsource/dejavu-mono@5.3.0/latin-400.css",
            "@fontsource/dejavu-mono@5.3.0/latin-700.css",
        ),
        works=(
            ("archlinux", "Arch Linux"),
            ("manjaro", "Manjaro"),
            ("endeavouros", "EndeavourOS"),
        ),
        favicon="#1793D1",
        logo=("#1793D1", "#1793D1"),
        css="""
body{--hd-font-body:"Liberation Sans",Arial,Helvetica,sans-serif;--hd-font-display:"DejaVu Sans",Verdana,sans-serif;--hd-font-mono:"DejaVu Sans Mono",ui-monospace,monospace;
--hd-h-weight:700;--hd-radius:.2rem;--hd-btn-radius:.2rem;--hd-pill:.2rem;--hd-step-radius:.2rem;
--hd-bg:#F6F9FC;--hd-fg:#222;--hd-muted:#555;--hd-surface:#ECF2F5;--hd-border:#BBCCDD;--hd-link:#0077BB;--hd-focus:#0077BB;--hd-accent:#1793D1;
--hd-bar-bg:#333;--hd-bar-fg:#CCC;--hd-bar-hover:rgba(255,255,255,.08);--hd-bar-current-bg:transparent;--hd-bar-current-fg:#fff;--hd-bar-rule:5px solid #0088CC;
--hd-hero-bg:#ECF2F5;--hd-hero-fg:#222;--hd-hero-muted:#555;--hd-hero-mark:#1793D1;--hd-hero-link:#005f96;
--hd-code-bg:#DDFFDD;--hd-code-fg:#222;--hd-code-border:#BBDDBB;--hd-inline-code-bg:#FFFFDD;--hd-code-btn-bg:#0077BB;--hd-code-btn-fg:#fff;--hd-code-btn-border:#0077BB;--hd-code-btn-hover:#005f96;--hd-tag-fg:#222;--hd-tag-bg:#BBDDBB;
--hd-btn-bg:#0077BB;--hd-btn-fg:#fff;--hd-btn-hover:#005f96;--hd-step-bg:#0077BB;--hd-step-fg:#fff;--hd-fp-tail:#005f96;--hd-panel-bg:#fff;
--hd-tab-active-bg:#fff;--hd-tab-active-fg:#222}
.masthead{padding-block:1.75rem 1.5rem;border-bottom:1px solid var(--hd-border)}
.masthead h1{font-size:clamp(1.45rem,3.5vw,2.25rem)}
.hero-card{background:#fff}
.masthead .lead{font-size:1.05rem}
.section{padding-block:1.75rem}
h2{font-size:1.6rem;padding-bottom:.35rem;border-bottom:1px solid var(--hd-border);margin-bottom:1rem}
h3{font-size:1.25rem}
.tablist{border-bottom:0;gap:.25rem;margin-bottom:0}
.tablist a{border:1px solid var(--hd-border);border-bottom:0;background:var(--hd-surface);margin-bottom:-1px;border-radius:.2rem .2rem 0 0;position:relative;z-index:1}
.tablist a.is-selected{background:var(--hd-panel-bg);border-bottom:1px solid var(--hd-panel-bg);box-shadow:inset 0 3px 0 var(--hd-accent)}
.panel{background:var(--hd-panel-bg);border:1px solid var(--hd-border);padding:1.5rem;border-radius:.2rem}
.tablist~.panel{border-top-left-radius:0}
.pkg div,.fp,.fold,.tree-wrap{background:var(--hd-surface)}
.tree li:hover>a,.tree li>details>summary:hover{background:#E4EEFF}
.tree-wrap{border:1px solid var(--hd-border)}
.foot{background:#333;color:#CCC;border-top:5px solid #0088CC}.foot a{color:#fff}
@media (max-width:640px){.panel{padding:1rem}}
"""
        + dark("""SEL body{--hd-bg:#050A10;--hd-fg:#EAECF0;--hd-muted:#b3bac3;--hd-surface:#0d141b;--hd-border:#384756;--hd-guide:#5a7390;--hd-link:#00B6F9;--hd-focus:#00B6F9;--hd-hero-bg:#060606;--hd-card-bg:#0d141b;--hd-hero-fg:#EAECF0;--hd-hero-muted:#b3bac3;--hd-hero-link:#00B6F9;--hd-code-bg:#181C20;--hd-code-fg:#EAECF0;--hd-code-border:#384756;--hd-inline-code-bg:#181C20;--hd-tag-fg:#EAECF0;--hd-tag-bg:#384756;--hd-panel-bg:#060606;--hd-fp-tail:#00B6F9;--hd-tab-active-bg:#060606;--hd-tab-active-fg:#EAECF0}
SEL .tree li:hover>a,SEL .tree li>details>summary:hover{background:#181C20}SEL .hero-card{background:#0d141b}"""),
    ),
    "apk": Theme(
        label="Alpine Linux",
        short="Alpine",
        icon=MARKS["apk"],
        mu="@digicreon/mucss@1.4.9/dist/mu.azure.css",
        fonts=(
            "@fontsource/arimo@5.3.0/latin-400.css",
            "@fontsource/arimo@5.3.0/latin-700.css",
            "@fontsource/cousine@5.3.0/latin-400.css",
            "@fontsource/cousine@5.3.0/latin-700.css",
            "@fontsource/comfortaa@5.3.0/latin-700.css",
        ),
        works=(
            ("alpinelinux", "Alpine Linux"),
            (None, "postmarketOS"),
        ),
        favicon="#0D597F",
        logo=("#0D597F", "#7FC0E3"),
        css="""
body{--hd-font-body:Arimo,Arial,Helvetica,sans-serif;--hd-font-display:Comfortaa,Arimo,Arial,sans-serif;--hd-font-mono:Cousine,"Courier New",monospace;
--hd-h-weight:700;--hd-radius:.25rem;--hd-btn-radius:.25rem;--hd-pill:999px;--hd-step-radius:50%;
--hd-bg:#fff;--hd-fg:#111;--hd-muted:#526066;--hd-surface:#f7f7f7;--hd-border:#e7e7e7;--hd-link:#0d597f;--hd-focus:#3d92c9;--hd-accent:#0d597f;
--hd-bar-bg:#fff;--hd-bar-fg:#0d597f;--hd-bar-hover:#eaf3f8;--hd-bar-current-bg:transparent;--hd-bar-current-fg:#111;--hd-bar-current-rule:3px;--hd-bar-rule:3px solid #0d597f;--hd-pill:.25rem;
--hd-hero-bg:#0d597f;--hd-hero-fg:#fff;--hd-hero-muted:#d6e7f0;--hd-hero-mark:#fff;--hd-hero-rule:#7fc0e3;
--hd-code-bg:#f2f2f2;--hd-code-fg:#111;--hd-code-border:#dcdcdc;--hd-code-btn-bg:#006f3a;--hd-code-btn-fg:#fff;--hd-code-btn-border:#006f3a;--hd-code-btn-hover:#00572d;--hd-tag-fg:#526066;--hd-tag-bg:#e7e7e7;
--hd-btn-bg:#006f3a;--hd-btn-fg:#fff;--hd-btn-hover:#00572d;--hd-step-bg:#0d597f;--hd-step-fg:#fff;--hd-fp-tail:#0d597f;
--hd-tab-active-bg:#0d597f;--hd-tab-active-fg:#fff}
h3,h4{font-family:Arimo,Arial,sans-serif}
.masthead{padding-block:clamp(2rem,4vw,3.5rem)}
.masthead h1{letter-spacing:-.01em}
h2{font-size:1.6rem}
.steps>li::before{border-radius:0;clip-path:polygon(20% 0,80% 0,100% 50%,80% 100%,20% 100%,0 50%);width:2.4rem}
.fold>summary,.fold[open]>summary{font-family:var(--hd-font-body)}
.hero-card{border:0}
.pkg div,.fp,.fold,.tree-wrap,.code{border-radius:0}
.copy{border-radius:.25rem}
.tablist{border-bottom:0;gap:.6rem}
.tablist a{border:1px solid var(--hd-border);border-radius:999px;margin-bottom:0}
.tablist a.is-selected{border-color:var(--hd-accent)}
.code{border-left:4px solid var(--hd-accent)}
.foot{background:#111;color:#cfd8dc;border-top:0}.foot a{color:#fff}
"""
        + dark("""SEL body{--hd-bg:#0b1a24;--hd-fg:#e6f1f7;--hd-muted:#a9c0cd;--hd-bar-bg:#0b1a24;--hd-bar-fg:#e6f1f7;--hd-bar-hover:#102a3a;--hd-bar-current-bg:transparent;--hd-bar-current-fg:#fff;--hd-bar-rule:3px solid #7fc0e3;--hd-accent:#7fc0e3;--hd-card-bg:#102a3a;--hd-surface:#102a3a;--hd-border:#1f4052;--hd-guide:#4f7f99;--hd-link:#7fc0e3;--hd-code-bg:#102a3a;--hd-code-fg:#e6f1f7;--hd-code-border:#1f4052;--hd-tag-fg:#e6f1f7;--hd-tag-bg:#1f4052;--hd-fp-tail:#7fc0e3;--hd-step-bg:#7fc0e3;--hd-step-fg:#0b1a24;--hd-tab-active-bg:#7fc0e3;--hd-tab-active-fg:#0b1a24}
SEL .code{border-left-color:#7fc0e3}"""),
    ),
    "flatpak": Theme(
        label="Flatpak",
        short="Flatpak",
        icon=MARKS["flatpak"],
        mu="@digicreon/mucss@1.4.9/dist/mu.azure.css",
        fonts=(
            "@fontsource-variable/inter@5.3.0/index.css",
            "@fontsource/jetbrains-mono@5.3.0/latin-400.css",
            "@fontsource/jetbrains-mono@5.3.0/latin-700.css",
        ),
        works=(
            ("flatpak", "Flatpak"),
            ("flathub", "Flathub"),
            ("gnome", "GNOME"),
            ("kde", "KDE"),
        ),
        favicon="#4A90D9",
        logo=("#4A90D9", "#4A90D9"),
        css="""
body{--hd-font-body:"Inter Variable",Inter,system-ui,sans-serif;--hd-font-display:var(--hd-font-body);--hd-font-mono:"JetBrains Mono",ui-monospace,Menlo,monospace;
--hd-h-weight:800;--hd-h-tracking:-.02em;--hd-radius:.75rem;--hd-btn-radius:999px;--hd-pill:999px;--hd-step-radius:50%;
--hd-bg:#fff;--hd-fg:#000;--hd-muted:#3d3846;--hd-surface:#f6f5f4;--hd-border:#deddda;--hd-link:#1a5fb4;--hd-focus:#4a90d9;--hd-accent:#4a90d9;
--hd-bar-bg:#fff;--hd-bar-fg:#000;--hd-bar-hover:#f6f5f4;--hd-bar-current-bg:#000;--hd-bar-current-fg:#fff;--hd-bar-rule:0 solid transparent;
--hd-hero-bg:#4a90d9;--hd-hero-fg:#000;--hd-hero-muted:#0b1f33;--hd-hero-mark:#fff;
--hd-code-bg:#241f31;--hd-code-fg:#fff;--hd-code-border:#241f31;--hd-code-btn-bg:#fff;--hd-code-btn-fg:#000;--hd-code-btn-border:#fff;--hd-code-btn-hover:#deddda;--hd-tag-fg:#fff;--hd-tag-bg:#3d3846;
--hd-btn-bg:#000;--hd-btn-fg:#fff;--hd-btn-hover:#3d3846;--hd-step-bg:#000;--hd-step-fg:#fff;--hd-fp-tail:#1a5fb4;
--hd-tab-active-bg:#000;--hd-tab-active-fg:#fff;--hd-tree-head:#fff}
.masthead h1{letter-spacing:-.015em}
.hero-card{border:0;border-radius:.75rem}
.tree-wrap{border:1px solid var(--hd-border)}
.tree-wrap .tree{background:var(--hd-bg)}
.tree-sum{background:var(--hd-surface)}
@media (max-width:640px){.panel .lead-install,.panel .pkg div,.panel .fp{background:var(--hd-surface);border:1px solid var(--hd-border)}.lead-install{padding:1rem 1rem .1rem}}
.masthead .lead{font-weight:500}.masthead .lead a{font-weight:700}
.pkg div{border-radius:.75rem}
.tablist{border-bottom:0;gap:.6rem}
.tablist a{border-radius:999px;background:var(--hd-surface);margin-bottom:0}
.panel{background:var(--hd-surface);padding:clamp(1rem,3vw,2rem);border-radius:.75rem}
.pkg div{background:var(--hd-bg);border-color:transparent}
.fp{background:var(--hd-bg);border:0}
.alt{margin:1.75rem 0 1.25rem;font-size:1.25rem;padding-top:1.25rem;border-top:1px solid var(--hd-border)}
.lead-install{background:var(--hd-bg);border-radius:.75rem;padding:1.25rem 1.25rem .35rem;margin-bottom:1.75rem}
.foot{background:#1a1622;color:#deddda;border-top:0}.foot a{color:#fff}
"""
        + dark("""SEL body{--hd-bg:#241f31;--hd-fg:#fff;--hd-muted:#cdc7d6;--hd-card-bg:#1a1622;--hd-bar-bg:#1a1622;--hd-bar-fg:#fff;--hd-bar-hover:#3d3846;--hd-bar-current-bg:#4a90d9;--hd-bar-current-fg:#000;--hd-surface:#3d3846;--hd-border:#5e5c64;--hd-guide:#8a8591;--hd-link:#62a0ea;--hd-code-bg:#1a1622;--hd-code-border:#3d3846;--hd-code-btn-bg:#4a90d9;--hd-code-btn-fg:#000;--hd-code-btn-border:#4a90d9;--hd-code-btn-hover:#99c1f1;--hd-btn-bg:#4a90d9;--hd-btn-fg:#000;--hd-btn-hover:#99c1f1;--hd-step-bg:#4a90d9;--hd-step-fg:#000;--hd-fp-tail:#99c1f1;--hd-tab-active-bg:#4a90d9;--hd-tab-active-fg:#000;--hd-tree-head:#241f31}
SEL .panel a{color:#99c1f1}SEL .pkg div,SEL .fp,SEL .lead-install{background:#1a1622}@media (max-width:640px){SEL .panel .lead-install,SEL .panel .pkg div,SEL .panel .fp{background:#3d3846;border-color:#5e5c64}}"""),
    ),
    "brew": Theme(
        label="Homebrew",
        short="Brew",
        icon=MARKS["brew"],
        mu="@digicreon/mucss@1.4.9/dist/mu.orange.css",
        fonts=(),
        works=(
            ("homebrew", "Homebrew"),
            ("apple", "macOS"),
        ),
        favicon="#2E2A24",
        logo=("#A8700F", "#E2A843"),
        css="""
body{--hd-font-body:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Helvetica Neue",Roboto,sans-serif;--hd-font-display:var(--hd-font-body);--hd-font-mono:ui-monospace,"SF Mono",Monaco,Menlo,Consolas,monospace;
--hd-h-weight:800;--hd-h1-weight:900;--hd-h3-weight:700;--hd-h4-weight:700;--hd-radius:.4em;--hd-btn-radius:.4em;--hd-pill:.4em;--hd-step-radius:50%;
--hd-bg:#fdf8ee;--hd-fg:#2e2a24;--hd-muted:#655539;--hd-surface:#f5ecda;--hd-border:#e0cfae;--hd-link:#745626;--hd-focus:#3d8ea3;--hd-accent:#e2a843;--hd-h2-color:#745626;
--hd-bar-bg:#24201b;--hd-bar-fg:#ffd79a;--hd-bar-hover:rgba(255,255,255,.08);--hd-bar-current-bg:#e2a843;--hd-bar-current-fg:#2e2a24;
--hd-hero-bg:#2e2a24;--hd-hero-fg:#ffd79a;--hd-hero-muted:#d8bf8c;--hd-hero-mark:#ffd79a;--hd-hero-link:#f7c96c;--hd-hero-rule:#e2a843;
--hd-code-bg:#2e2a24;--hd-code-fg:#ffd79a;--hd-code-border:#2e2a24;--hd-code-btn-bg:#e2a843;--hd-code-btn-fg:#2e2a24;--hd-code-btn-border:#e2a843;--hd-code-btn-hover:#f7c96c;--hd-tag-fg:#ffd79a;--hd-tag-bg:rgba(0,0,0,.3);
--hd-btn-bg:#e2a843;--hd-btn-fg:#2e2a24;--hd-btn-hover:#f7c96c;--hd-step-bg:#2e2a24;--hd-step-fg:#ffd79a;--hd-fp-tail:#745626;
--hd-tab-active-bg:#2e2a24;--hd-tab-active-fg:#ffd79a}
.masthead{border-bottom:4px solid var(--hd-accent)}
.masthead h1{letter-spacing:-.01em;text-shadow:1px 1px 10px rgba(0,0,0,.25)}
.hero-card{border:0;border-top:4px solid var(--hd-accent)}
h2{color:var(--hd-h2-color)}
a{font-weight:600}
.tablist a{border-bottom-width:3px}
.pkg div{border-top:3px solid var(--hd-accent)}
.foot{background:#24201b;color:#d8bf8c;border-top:0}.foot a{color:#f7c96c}
"""
        + dark(
            """SEL body{--hd-bg:#2e2a24;--hd-fg:#ffd79a;--hd-muted:#d1b98a;--hd-surface:#38332b;--hd-border:#574c3b;--hd-guide:#7a6a50;--hd-link:#e2a843;--hd-focus:#87c7d8;--hd-h2-color:#ffd79a;--hd-card-bg:#38332b;--hd-hero-bg:#24201b;--hd-code-bg:#1f1c18;--hd-code-border:#4a4135;--hd-inline-code-bg:#1f1c18;--hd-fp-tail:#f7c96c;--hd-tab-active-bg:#e2a843;--hd-tab-active-fg:#2e2a24;--hd-step-bg:#e2a843;--hd-step-fg:#2e2a24}"""
        ),
    ),
    "scoop": Theme(
        label="Scoop",
        short="Scoop",
        icon=SCOOP_MARK,
        mu="@digicreon/mucss@1.4.9/dist/mu.azure.css",
        fonts=(),
        works=(
            (None, "Scoop"),
            (None, "Windows"),
        ),
        favicon="#4D4A52",
        logo=("#D9488F", "#F77FB5"),
        css="""
body{--hd-font-body:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;--hd-font-display:var(--hd-font-body);--hd-font-mono:SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;
--hd-h-weight:500;--hd-h1-weight:700;--hd-h3-weight:600;--hd-h4-weight:600;--hd-radius:.375rem;--hd-btn-radius:.375rem;--hd-pill:.375rem;--hd-step-radius:50%;
--hd-bg:#fff;--hd-fg:#212529;--hd-muted:#5c5866;--hd-surface:#f8f9fa;--hd-border:#dee2e6;--hd-link:#0a58ca;--hd-focus:#86b7fe;--hd-accent:#f77fb5;--hd-h2-color:#6b4fa3;
--hd-bar-bg:#2b2930;--hd-bar-fg:#fff;--hd-bar-hover:rgba(255,255,255,.1);--hd-bar-current-bg:#f77fb5;--hd-bar-current-fg:#2b2930;
--hd-hero-bg:#4d4a52;--hd-hero-fg:#fff;--hd-hero-muted:#d9d6dc;--hd-hero-mark:#f77fb5;--hd-hero-link:#e9ee9e;--hd-hero-rule:#e9ee9e;
--hd-code-bg:#f8f9fa;--hd-code-fg:#212529;--hd-code-border:#dee2e6;--hd-code-btn-bg:#e9ecef;--hd-code-btn-fg:#212529;--hd-code-btn-border:#e9ecef;--hd-code-btn-hover:#dee2e6;--hd-tag-fg:#212529;--hd-tag-bg:#e9ecef;
--hd-btn-bg:#6b4fa3;--hd-btn-fg:#fff;--hd-btn-hover:#58408a;--hd-step-bg:#8a6ac0;--hd-step-fg:#fff;--hd-fp-tail:#6b4fa3;
--hd-tab-active-bg:#4d4a52;--hd-tab-active-fg:#fff}
.masthead{border-bottom:4px solid var(--hd-accent);box-shadow:inset 0 -8px 0 #8a6ac0,inset 0 -12px 0 #e9ee9e}
.hero-card{border:0;border-top:4px solid var(--hd-accent)}
h2{color:var(--hd-h2-color)}
a:not([class]){text-decoration:none}a:not([class]):hover{text-decoration:underline}
.tablist a{border-bottom-width:3px}
.pkg div{border-top:3px solid var(--hd-accent)}
"""
        + dark(
            """SEL body{--hd-bg:#222;--hd-fg:#e1e1e1;--hd-muted:#b4b0bb;--hd-surface:#2b2930;--hd-border:#495057;--hd-guide:#6c757d;--hd-link:#6ea8fe;--hd-h2-color:#c9b3f0;--hd-card-bg:#38353e;--hd-hero-bg:#2b2930;--hd-code-bg:#343a40;--hd-code-fg:#e1e1e1;--hd-code-border:#495057;--hd-code-btn-bg:#495057;--hd-code-btn-fg:#e1e1e1;--hd-code-btn-border:#495057;--hd-code-btn-hover:#6c757d;--hd-inline-code-bg:#343a40;--hd-tag-fg:#e1e1e1;--hd-tag-bg:#495057;--hd-fp-tail:#c9b3f0;--hd-tab-active-bg:#f77fb5;--hd-tab-active-fg:#2b2930;--hd-btn-bg:#8a6ac0;--hd-btn-hover:#a68ad6;--hd-tree-head:#2b2930}"""
        ),
    ),
    "nix": Theme(
        label="Nix",
        short="Nix",
        icon=MARKS["nix"],
        mu="@digicreon/mucss@1.4.9/dist/mu.azure.css",
        fonts=(
            "@fontsource-variable/inter@5.3.0/index.css",
            "@fontsource/jetbrains-mono@5.3.0/latin-400.css",
            "@fontsource/jetbrains-mono@5.3.0/latin-700.css",
        ),
        works=(
            ("nixos", "NixOS"),
            ("linux", "Linux"),
            ("apple", "macOS"),
        ),
        favicon="#5277C3",
        logo=("#5277C3", "#7EBAE4"),
        css="""
body{--hd-font-body:"Inter Variable",Inter,system-ui,sans-serif;--hd-font-display:var(--hd-font-body);--hd-font-mono:"JetBrains Mono",ui-monospace,Menlo,monospace;
--hd-brand:#5277c3;--hd-brand-light:#7ebae4;
--hd-h-weight:700;--hd-h1-weight:800;--hd-h2-weight:700;--hd-h3-weight:700;--hd-h4-weight:600;--hd-h-tracking:-.015em;--hd-radius:.375rem;--hd-btn-radius:.375rem;--hd-pill:.375rem;--hd-step-radius:.375rem;
--hd-bg:#fff;--hd-fg:#111827;--hd-muted:#475569;--hd-surface:#f1f5f9;--hd-border:#cbd5e1;--hd-link:#2d5299;--hd-focus:#5277c3;--hd-accent:var(--hd-brand);--hd-h2-color:#1e3a6e;
--hd-bar-bg:#111c2d;--hd-bar-fg:#f8fafc;--hd-bar-hover:rgba(126,186,228,.14);--hd-bar-current-bg:var(--hd-brand-light);--hd-bar-current-fg:#111c2d;--hd-bar-rule:1px solid #243856;
--hd-hero-bg:#182842;--hd-hero-fg:#fff;--hd-hero-muted:#c7daf0;--hd-hero-mark:var(--hd-brand-light);--hd-hero-link:#9ed0f5;--hd-hero-rule:var(--hd-brand);
--hd-code-bg:#111c2d;--hd-code-fg:#f1f5f9;--hd-code-border:#1e314d;--hd-code-btn-bg:var(--hd-brand-light);--hd-code-btn-fg:#111c2d;--hd-code-btn-border:var(--hd-brand-light);--hd-code-btn-hover:#a5d1f0;--hd-tag-fg:#e2e8f0;--hd-tag-bg:#243856;
--hd-btn-bg:#2d5299;--hd-btn-fg:#fff;--hd-btn-hover:#1e3a6e;--hd-step-bg:#2d5299;--hd-step-fg:#fff;--hd-fp-tail:#254685;
--hd-tab-active-bg:transparent;--hd-tab-active-fg:#111827}
.masthead{border-bottom:4px solid var(--hd-brand)}
.masthead::before{content:"";position:absolute;inset:0;background:linear-gradient(120deg,transparent 62%,#213759 62%,#213759 74%,#142238 74%);pointer-events:none}
@media (max-width:900px){.masthead::before{display:none}}
.masthead h1{letter-spacing:-.02em}
.hero-card{border:0;border-top:3px solid var(--hd-brand)}
h2{color:var(--hd-h2-color)}
.tablist a{border-bottom-width:3px}
.pkg div{border-top:3px solid var(--hd-brand)}
.code .tok{max-width:100%;white-space:pre-wrap;overflow-wrap:anywhere}
.foot{background:#111c2d;color:#c7daf0;border-top:3px solid var(--hd-brand)}.foot a{color:var(--hd-brand-light)}
"""
        + dark("""SEL body{--hd-bg:#0f1724;--hd-fg:#e6eef8;--hd-muted:#a3b6cc;--hd-surface:#172336;--hd-card-bg:#172336;--hd-border:#2b3f5c;--hd-guide:#4a658a;--hd-link:var(--hd-brand-light);--hd-focus:var(--hd-brand-light);--hd-accent:var(--hd-brand-light);--hd-h2-color:#e6eef8;--hd-hero-bg:#132035;--hd-code-bg:#0a101a;--hd-code-border:#243856;--hd-inline-code-bg:#172336;--hd-btn-bg:var(--hd-brand-light);--hd-btn-fg:#0f1724;--hd-btn-hover:#a5d1f0;--hd-step-bg:var(--hd-brand-light);--hd-step-fg:#0f1724;--hd-fp-tail:var(--hd-brand-light);--hd-tab-active-fg:#e6eef8;--hd-tree-head:#132035}
SEL .masthead::before{background:linear-gradient(120deg,transparent 62%,#1a2c47 62%,#1a2c47 74%,#0f1a2b 74%)}"""),
    ),
}

BASE_CSS = """
:root{--mu-font-size:100%}
body>header,body>main,body>footer{padding-block:0}
html.no-js .copy{display:none}
body{--mu-background-color:var(--hd-bg);--mu-color:var(--hd-fg);--mu-muted-color:var(--hd-muted);--mu-primary:var(--hd-link);--mu-primary-hover:var(--hd-link);--mu-primary-underline:var(--hd-link);--mu-primary-focus:var(--hd-focus);--mu-border-color:var(--hd-border);--mu-muted-border-color:var(--hd-border);--mu-code-background-color:var(--hd-inline-code-bg,var(--hd-surface));--mu-code-color:var(--hd-fg);--mu-font-family:var(--hd-font-body);--mu-font-family-monospace:var(--hd-font-mono);--mu-h1-color:var(--hd-fg);--mu-h2-color:var(--hd-fg);--mu-h3-color:var(--hd-fg);--mu-h4-color:var(--hd-fg);--mu-border-radius:var(--hd-radius);--mu-accordion-close-summary-color:var(--hd-fg);--mu-accordion-open-summary-color:var(--hd-fg);--mu-accordion-active-summary-color:var(--hd-fg);
margin:0;min-height:100vh;display:flex;flex-direction:column;background:var(--hd-bg);color:var(--hd-fg);font-family:var(--hd-font-body);font-size:1rem;line-height:1.55;-webkit-font-smoothing:antialiased}
h1,h2,h3,h4{font-family:var(--hd-font-display);font-weight:var(--hd-h-weight);letter-spacing:var(--hd-h-tracking,0);text-wrap:balance;color:var(--hd-fg);margin-top:0}
h2{font-size:1.85rem;margin-bottom:1rem;font-weight:var(--hd-h2-weight,var(--hd-h-weight))}
h3{font-size:1.4rem;margin-bottom:.25rem;font-weight:var(--hd-h3-weight,var(--hd-h-weight))}
h4{font-size:1.1rem;margin-bottom:.4rem;font-weight:var(--hd-h4-weight,var(--hd-h-weight))}
p{margin:0 0 1rem}
a{color:var(--hd-link);text-decoration-thickness:1px;text-underline-offset:.15em;transition:none}
a:hover{text-decoration-thickness:2px}
code.nw{white-space:nowrap}
code{font-family:var(--hd-font-mono);font-size:.92em;padding:.1em .2em;margin-right:-.05em;border-radius:.2rem;background:var(--hd-inline-code-bg,var(--hd-surface));color:var(--hd-fg)}
*:focus-visible{outline:3px solid var(--hd-focus);outline-offset:2px;box-shadow:none}
.wrap{width:min(100% - 2.5rem,72rem);margin-inline:auto}
.skip{position:absolute;left:1rem;top:-10rem;z-index:10;padding:.6rem 1rem;background:var(--hd-bg);color:var(--hd-fg);border:2px solid var(--hd-focus);border-radius:var(--hd-radius)}
.skip:focus{top:1rem}
.vh{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}

/* Switcher bar */
.bar{background:var(--hd-bar-bg);color:var(--hd-bar-fg);border-bottom:var(--hd-bar-rule,0 solid transparent)}
.bar .wrap{display:flex;align-items:center;justify-content:space-between;gap:1rem;min-height:3.5rem;padding-block:.5rem}
.bar ul{color:inherit}
.bar nav{min-width:0}
.brand{display:inline-flex;align-items:center;gap:.6rem;color:inherit;text-decoration:none;font-weight:700;font-family:var(--hd-font-display);letter-spacing:0;font-size:1rem;flex:none}
.brand:hover{text-decoration:none}
.brand svg{width:1.25rem;height:1.25rem}
.bar .sites{display:flex;gap:.6rem;list-style:none;margin:0;padding:0;flex-wrap:wrap;min-width:0;width:100%;justify-content:flex-end}
.sites .short{display:none}
.bar .sites li{margin:0;padding:0;list-style:none;flex:none}
.bar .sites li a{display:inline-flex;align-items:center;gap:.45rem;margin:0;padding:.4rem .75rem;border-radius:var(--hd-pill,var(--hd-radius));color:var(--hd-bar-fg);text-decoration:none;font-size:.9rem;font-weight:500;line-height:1.2;white-space:nowrap}
.bar .sites li a:hover{background:var(--hd-bar-hover);text-decoration:none}
.bar .sites li a[aria-current]{background:var(--hd-bar-current-bg);color:var(--hd-bar-current-fg);font-weight:700;box-shadow:inset 0 calc(-1 * var(--hd-bar-current-rule,0px)) 0 var(--hd-accent)}
.sites svg{width:1rem;height:1rem;fill:currentColor;flex:none}

/* Masthead */
.masthead{position:relative;overflow:hidden;background:var(--hd-hero-bg);color:var(--hd-hero-fg);padding-block:clamp(2.25rem,6vw,4.5rem) clamp(2rem,5vw,3.5rem)}
.masthead ul,.masthead p,.masthead dl{color:inherit}
.masthead .wrap{position:relative;display:grid;grid-template-columns:auto minmax(0,1fr) minmax(17rem,22rem);gap:1.5rem 2.25rem;align-items:start}
.hero-card{background:var(--hd-card-bg,var(--hd-bg));color:var(--hd-fg);border:1px solid var(--hd-border);border-radius:var(--hd-radius);padding:1.25rem 1.5rem 1.35rem;align-self:center;position:relative}
.hero-card h2{font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;color:var(--hd-muted);margin:0 0 1rem;font-weight:600;font-family:var(--hd-font-body)}
.hero-card dl{display:grid;grid-template-columns:auto auto;justify-content:space-between;gap:1rem 1.5rem;margin:0;color:inherit}
.hero-card dt{font-size:.75rem;color:var(--hd-muted);margin:0 0 .15rem}
.hero-card dd{margin:0;font-weight:700;font-size:1.3rem;line-height:1.25;font-variant-numeric:tabular-nums}
.hero-card dd small{font-weight:400;font-size:.8rem;color:var(--hd-muted)}
.masthead .mark{width:clamp(4rem,9vw,6.5rem);height:clamp(4rem,9vw,6.5rem);fill:var(--hd-hero-mark);flex:none;margin-top:.25rem}
.masthead h1{color:inherit;font-size:clamp(2rem,5.2vw,3.5rem);line-height:1.05;margin:0 0 .75rem;font-weight:var(--hd-h1-weight,var(--hd-h-weight));text-wrap:pretty}
.masthead h1 span{display:block}
.masthead .lead{font-size:clamp(1.05rem,1.9vw,1.3rem);margin:0 0 1.5rem;color:inherit;max-width:52ch;text-wrap:pretty}
.works{display:flex;flex-wrap:wrap;align-items:center;gap:.6rem 1.1rem;margin:0;padding:0;list-style:none;font-size:.95rem}
.works li{display:inline-flex;align-items:center;gap:.45rem;margin:0;padding:0;list-style:none}
.works .label{color:var(--hd-hero-muted)}
.works i{display:inline-block;width:1.15rem;height:1.15rem;background:currentColor;-webkit-mask:var(--m) center/contain no-repeat;mask:var(--m) center/contain no-repeat}
.works .txt{font-weight:600;font-size:.82em;border:1px solid currentColor;border-radius:.2rem;padding:.05rem .4rem;opacity:.9}
.masthead .lead a{color:var(--hd-hero-link,inherit);font-weight:600;text-decoration:underline;text-decoration-color:var(--hd-hero-rule,currentColor);text-decoration-thickness:2px;text-underline-offset:.2em;white-space:nowrap}
.masthead .lead a:hover{text-decoration-color:currentColor;text-decoration-thickness:3px}
.masthead .lead a:focus-visible{outline-color:currentColor;border-radius:.1rem}

/* Sections */
main{flex:1}
.section{padding-block:clamp(2rem,4vw,2.75rem)}
.section+.section{border-top:1px solid var(--hd-border)}
.section h2{margin-bottom:1rem}

/* Project tabs */
.tablist{display:flex;gap:.25rem;flex-wrap:wrap;margin:0 0 1.5rem;padding:0;list-style:none;border-bottom:1px solid var(--hd-border)}
.tablist li{margin:0;padding:0;list-style:none}
.tablist a{display:inline-flex;flex-direction:column;align-items:flex-start;gap:.1rem;padding:.75rem 1.3rem;color:var(--hd-fg);text-decoration:none;font-family:var(--hd-font-display);letter-spacing:0;border-bottom:3px solid transparent;margin-bottom:-1px;line-height:1.2;min-width:8rem}
html:not(.no-js) .tablist a,html:not(.no-js) .tablist a:link,html:not(.no-js) .tablist a:visited,html:not(.no-js) .tablist a:focus{color:var(--hd-fg);text-decoration:none}
html:not(.no-js) .tablist a.is-selected,html:not(.no-js) .tablist a.is-selected:link,html:not(.no-js) .tablist a.is-selected:visited,html:not(.no-js) .tablist a.is-selected:focus{color:var(--hd-tab-active-fg)}
.tablist a:hover{background:var(--hd-surface);text-decoration:none}
.tablist a.is-selected{border-bottom-color:var(--hd-accent);background:var(--hd-tab-active-bg);color:var(--hd-tab-active-fg)}
html.no-js .tablist{border:0;gap:1rem;margin-bottom:1rem}html.no-js .tablist::before{content:"Jump to";align-self:center;color:var(--hd-muted);font-size:.9rem}html.no-js .tablist a,html.no-js .tablist a.is-selected{border:0;background:none;color:var(--hd-link);min-width:0;padding:.25rem 0;flex-direction:row;gap:.4rem;align-items:baseline;text-decoration:underline;box-shadow:none;border-radius:0}html.no-js .tablist .t-name{font-weight:600;font-size:1rem}
.tablist .t-name{font-weight:500;font-size:1.1rem}
.tablist a.is-selected .t-name{font-weight:700}
.tablist .t-ver{font-family:var(--hd-font-mono);font-size:.8rem;color:var(--hd-muted)}
.tablist a.is-selected .t-ver{color:inherit;opacity:.8}
.panel[hidden],html:not(.no-js) .panel.is-hidden{display:none}
.no-js .panel+.panel{margin-top:3rem;padding-top:3rem;border-top:1px dashed var(--hd-border)}
.project{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:1rem 2rem;align-items:start;margin-bottom:2rem}
.project .desc{margin:.25rem 0 .6rem;color:var(--hd-muted);max-width:58ch;text-wrap:pretty}
.project .gh{display:inline-flex;align-items:center;gap:.4rem;font-weight:500}
.project .gh svg{width:1rem;height:1rem;fill:currentColor}
.pkg{display:flex;gap:.6rem;flex-wrap:wrap;margin:0}
.pkg div{background:var(--hd-surface);border:1px solid var(--hd-border);border-radius:var(--hd-radius);padding:.55rem .85rem;min-width:6.5rem}
.pkg dt{font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;color:var(--hd-muted);margin:0 0 .1rem;font-weight:600}
.pkg dd{margin:0;font-weight:700;font-family:var(--hd-font-mono);font-size:.92rem;color:var(--hd-fg)}

/* Steps */
.steps{list-style:none;margin:0;padding:0;counter-reset:step}
.steps>li{position:relative;padding-left:3.5rem;padding-bottom:1.75rem;margin:0}
.steps>li:last-child{padding-bottom:.25rem}
.steps>li::before{counter-increment:step;content:counter(step);position:absolute;left:0;top:-.15rem;width:2.4rem;height:2.4rem;border-radius:var(--hd-step-radius,50%);background:var(--hd-step-bg);color:var(--hd-step-fg);display:grid;place-items:center;font-weight:700;font-family:var(--hd-font-display);font-size:1.05rem;letter-spacing:0}
.steps>li:not(:last-child)::after{content:"";position:absolute;left:calc(1.2rem - 1px);top:2.6rem;bottom:.35rem;width:2px;background:var(--hd-border)}
.step-head{display:flex;align-items:center;justify-content:space-between;gap:.75rem 1.5rem;flex-wrap:wrap;margin:.35rem 0 .4rem}
.step-head h4{margin:0}
.steps h4{margin:.35rem 0 .4rem;font-size:1.05rem}
.steps .note{margin:0 0 .8rem;color:var(--hd-muted);max-width:80ch;text-wrap:pretty}

/* Code blocks */
.code{position:relative;margin:0 0 .9rem;background:var(--hd-code-bg);border:1px solid var(--hd-code-border);border-radius:var(--hd-radius);color:var(--hd-code-fg)}
.code pre{margin:0;padding:.95rem 1.1rem;background:none;color:inherit;font-size:.9rem;line-height:1.6;white-space:pre-wrap;overflow-wrap:normal;word-break:normal;overflow:visible}
.code pre::before{content:"";float:right;width:var(--hd-copy-space,5.5rem);height:1.4rem}
.code.tagged pre::before{width:calc(var(--hd-copy-space,5.5rem) + 4.25rem)}
.code code{display:block;padding:0;background:none;color:inherit;font-size:inherit;font-family:var(--hd-font-mono)}
.code .tok{display:inline-block;white-space:pre}
.code .tok.br{display:inline;white-space:normal}
.code .pm-tag{position:absolute;top:.6rem;right:calc(var(--hd-copy-space,5.5rem) + .3rem);height:1.75rem;display:inline-flex;align-items:center;font-size:.75rem;font-weight:700;letter-spacing:.04em;background:var(--hd-tag-bg);color:var(--hd-tag-fg);padding:0 .55rem;border-radius:var(--hd-btn-radius,.2rem)}
.copy{position:absolute;top:.6rem;right:.6rem;display:inline-flex;align-items:center;gap:.4rem;margin:0;width:auto;padding:.3rem .7rem;font-size:.8rem;font-weight:600;line-height:1.3;border-radius:var(--hd-btn-radius,var(--hd-radius));background:var(--hd-btn-bg);color:var(--hd-btn-fg);border:1px solid var(--hd-btn-bg);cursor:pointer;box-shadow:none;font-family:var(--hd-font-body);transition:background-color .15s ease}
.copy:hover{background:var(--hd-btn-hover);color:var(--hd-btn-fg)}
.code .copy{background:var(--hd-code-btn-bg,var(--hd-btn-bg));color:var(--hd-code-btn-fg,var(--hd-btn-fg));border-color:var(--hd-code-btn-border,var(--hd-code-btn-bg,var(--hd-btn-bg)))}
.code .copy:hover{background:var(--hd-code-btn-hover,var(--hd-btn-hover));color:var(--hd-code-btn-fg,var(--hd-btn-fg))}
.copy svg{width:.95rem;height:.95rem;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;flex:none}
.copy .ok{display:none}.copy.done .ok{display:block}.copy.done .ic{display:none}
.copy.done,.code .copy.done{background:var(--hd-fg);color:var(--hd-bg);border-color:var(--hd-fg)}
@media (max-width:640px){.code{--hd-copy-space:4.6rem}.code pre{padding:.85rem .9rem;font-size:.86rem}.copy{padding:.3rem .55rem;font-size:.75rem}}

/* Package manager switch (RPM) */
.pm{display:inline-flex;width:auto;gap:0;border:1px solid var(--hd-border);border-radius:var(--hd-btn-radius,var(--hd-radius));padding:.2rem;margin:0;background:var(--hd-surface);position:relative}
.pm legend{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%)}
.pm input{position:absolute;opacity:0;width:1px;height:1px;margin:0}
.pm label{padding:.3rem .9rem;border-radius:calc(var(--hd-btn-radius,var(--hd-radius)) - .1rem);cursor:pointer;font-weight:600;font-size:.85rem;margin:0;display:inline-block;color:var(--hd-fg)}
.pm input:checked+label{background:var(--hd-fg);color:var(--hd-bg)}
.pm input:focus-visible+label{outline:3px solid var(--hd-focus);outline-offset:2px}
.panel:has(.pm input[value=zypper]:checked) .for-dnf,.section:has(.panel:not([hidden]):not(.is-hidden) .pm input[value=zypper]:checked) .fold .for-dnf{display:none}
.panel:has(.pm input[value=dnf]:checked) .for-zypper,.section:has(.panel:not([hidden]):not(.is-hidden) .pm input[value=dnf]:checked) .fold .for-zypper{display:none}

/* Fingerprint */
.fp{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:.75rem 1rem;align-items:center;background:var(--hd-surface);border:1px solid var(--hd-border);border-left:4px solid var(--hd-accent);border-radius:var(--hd-radius);padding:.9rem 1.1rem;margin:0 0 .9rem}
.fp .fp-label{font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;color:var(--hd-muted);margin:0 0 .3rem;font-weight:600}
.fp .groups{display:flex;flex-wrap:wrap;gap:.25rem .65rem;font-family:var(--hd-font-mono);font-size:1.08rem;font-weight:700;letter-spacing:.03em;margin:0;color:var(--hd-fg)}
.fp .groups span.tail{color:var(--hd-fp-tail)}
.fp .fp-note{margin:.35rem 0 0;font-size:.8rem;color:var(--hd-muted)}
.fp .copy{position:static}

/* Fold */
.fold{border:1px solid var(--hd-border);border-radius:var(--hd-radius);background:var(--hd-surface);margin:1.5rem 0 0;padding:0}
.fold>summary,.fold[open]>summary{display:flex;align-items:center;gap:.75rem;padding:.9rem 1.25rem;margin:0;cursor:pointer;font-weight:700;font-family:var(--hd-font-display);font-size:1.05rem;line-height:1.3;list-style:none;color:var(--hd-fg)}
.fold>summary::-webkit-details-marker{display:none}
.fold>summary::after{display:none}
.fold>summary:focus-visible{outline:3px solid var(--hd-focus);outline-offset:-3px}
.fold>summary .chev{width:1rem;height:1rem;fill:none;stroke:currentColor;stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round;transition:transform .2s ease;flex:none}
.fold[open]>summary .chev{transform:rotate(90deg)}
.fold>summary .sub{font-weight:400;color:var(--hd-muted);font-size:.9rem;font-family:var(--hd-font-body);margin-left:auto;letter-spacing:0}
.fold .body{padding:0 1.25rem 1rem}
.fold .body p{color:var(--hd-muted);margin-bottom:.75rem}

/* File browser */
.tree-wrap{border:1px solid var(--hd-border);border-radius:var(--hd-radius);overflow:hidden;background:var(--hd-bg)}
.tree-sum{display:flex;justify-content:space-between;gap:1rem;flex-wrap:wrap;padding:.7rem 1rem;border-bottom:1px solid var(--hd-border);font-size:.875rem;color:var(--hd-muted);background:var(--hd-tree-head,var(--hd-surface))}
.tree-sum strong{color:var(--hd-fg);font-weight:700}
.tree,.tree ul{list-style:none;margin:0;padding:0}
.tree li{margin:0;padding:0;list-style:none}.tree li::marker{content:none}
.tree ul{margin-left:1rem;border-left:1px solid var(--hd-guide,var(--hd-border));padding-left:.2rem}
.tree details{margin:0;padding:0;border:0}
.tree details>summary,.tree details[open]>summary,.tree li>a,.tree .frow{display:grid;grid-template-columns:1.1rem 1.25rem minmax(0,1fr) auto;align-items:center;gap:.5rem;padding:.42rem .9rem .42rem .6rem;margin:0;color:var(--hd-fg);text-decoration:none;font-size:.92rem;line-height:1.35;cursor:pointer;border-radius:var(--hd-radius)}
.tree details>summary{list-style:none}
.tree details>summary::-webkit-details-marker{display:none}
.tree details>summary::after{display:none}
.tree details>summary:focus-visible,.tree li>a:focus-visible{outline:3px solid var(--hd-focus);outline-offset:-3px}
.tree .chev{width:.8rem;height:.8rem;fill:none;stroke:var(--hd-muted);stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round;transition:transform .15s ease;justify-self:center}
.tree details[open]>summary .chev{transform:rotate(90deg)}
.tree .ico{width:1.2rem;height:1.2rem;fill:none;stroke:currentColor;stroke-width:1.6;stroke-linejoin:round;stroke-linecap:round}
.tree .ico.folder{fill:color-mix(in srgb,var(--hd-accent) 22%,transparent);stroke:var(--hd-accent)}
.tree .ico.file{stroke:var(--hd-muted)}
.tree .ico.open{display:none}.tree details[open]>summary .ico.open{display:block}.tree details[open]>summary .ico.closed{display:none}
.tree .name{overflow-wrap:normal;min-width:0}
.tree details>summary .name{font-weight:700}
.tree li>a .name{text-decoration:underline;text-decoration-color:transparent;text-underline-offset:.15em}
.tree li>a:hover .name{text-decoration-color:currentColor}
.tree .meta{color:var(--hd-muted);font-size:.8rem;margin-left:.4rem;font-weight:400}
.tree .size{font-variant-numeric:tabular-nums;color:var(--hd-muted);font-size:.85rem;text-align:right;min-width:5.5rem;white-space:nowrap}
.tree li:hover>a,.tree li>details>summary:hover{background:var(--hd-surface)}
.tree .aux .name{color:var(--hd-muted)}
.tree .frow{cursor:default}

/* Footer */
.foot{border-top:1px solid var(--hd-border);padding:1.5rem 0;color:var(--hd-muted);font-size:.9rem}
.foot .wrap{display:flex;justify-content:space-between;gap:.5rem 1.5rem;flex-wrap:wrap}
.foot p{margin:0;color:inherit}
.foot a{color:inherit;font-weight:600}

@media (max-width:900px){.masthead .wrap{grid-template-columns:auto minmax(0,1fr)}.hero-card{grid-column:1/-1}.hero-card dl{grid-template-columns:repeat(4,auto);justify-content:space-between}.project{grid-template-columns:1fr}.fp{grid-template-columns:1fr}.fp .copy{justify-self:start}}
@media (max-width:640px){
.brand span{display:none}
.bar .wrap{gap:.5rem}
.bar nav{flex:1;min-width:0}
.bar .sites{gap:0;justify-content:space-between;flex-wrap:wrap}
.bar .sites li a{padding:.45rem .28rem;font-size:.8rem;gap:.25rem}
.works{gap:.4rem .7rem;font-size:.9rem}
.works .label{flex-basis:100%}
.sites svg{display:none}
.sites .full{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%)}.sites .short{display:inline}
.masthead .wrap{grid-template-columns:1fr;gap:1rem}
.hero-card{display:none}
.masthead .mark{width:3.75rem;height:3.75rem}
.pkg{display:grid;grid-template-columns:1fr 1fr}
.pkg div:nth-child(3n+1){grid-column:1/-1}
.pkg dd{font-size:.85rem}
.tablist a{min-width:0;flex:1}
.tablist li{flex:1}
.fold>summary .sub{display:none}
.steps>li{padding-left:3rem}
.steps>li::before{width:2.1rem;height:2.1rem;font-size:.95rem}
.steps>li:not(:last-child)::after{left:calc(1.05rem - 1px);top:2.35rem}
.tree ul{margin-left:.9rem;padding-left:.2rem}
.tree .meta{display:block;margin-left:0}
.steps>li{padding-left:0;padding-bottom:1.5rem}
.steps>li::before{position:static;float:left;width:1.75rem;height:1.75rem;margin:.05rem .6rem 0 0;font-size:.85rem}
.steps>li::after{display:none}
.steps h4,.step-head{min-height:1.85rem}
.steps .note,.steps .code,.steps .fp,.steps .pm{clear:both}
.step-head{align-items:flex-start}
.panel{padding:0!important;border:0!important;background:none!important;border-radius:0!important}
.lead-install{padding:.9rem .75rem .1rem}
}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{transition:none!important;animation:none!important;scroll-behavior:auto!important}}
"""

JS = """
document.documentElement.classList.remove('no-js');
(()=>{
const live=document.getElementById('copy-status');
for(const b of document.querySelectorAll('.copy')){
  b.addEventListener('click',async()=>{
    const text=b.dataset.copy??b.closest('.code').querySelector('code').textContent;
    const label=b.querySelector('span');
    try{await navigator.clipboard.writeText(text);b.classList.add('done');label.textContent='Copied';live.textContent='Copied to the clipboard.';}
    catch{label.textContent='Copy failed';live.textContent='Copy failed. Select the text and copy it.';}
    clearTimeout(b._t);b._t=setTimeout(()=>{b.classList.remove('done');label.textContent='Copy';},2000);
  });
}
for(const list of document.querySelectorAll('.tablist')){
  const tabs=[...list.querySelectorAll('a[data-panel]')];
  const panels=tabs.map(a=>document.getElementById(a.dataset.panel));
  if(panels.some(p=>!p))continue;
  list.setAttribute('role','tablist');
  tabs.forEach((a,i)=>{a.setAttribute('role','tab');a.setAttribute('aria-controls',panels[i].id);a.parentElement.setAttribute('role','presentation');panels[i].setAttribute('role','tabpanel');panels[i].tabIndex=0;});
  const select=(i,focus)=>{tabs.forEach((a,j)=>{const on=i===j;a.setAttribute('aria-selected',on?'true':'false');a.tabIndex=on?0:-1;a.classList.toggle('is-selected',on);panels[j].hidden=!on;panels[j].classList.remove('is-hidden');});if(focus)tabs[i].focus();};
  select(Math.max(0,tabs.findIndex(a=>a.classList.contains('is-selected'))),false);
  tabs.forEach((a,i)=>{
    a.addEventListener('click',ev=>{ev.preventDefault();select(i,false);history.replaceState(null,'','#'+panels[i].id);});
    a.addEventListener('keydown',ev=>{const n=tabs.length;let t=null;
      if(ev.key==='ArrowRight'||ev.key==='ArrowDown')t=(i+1)%n;else if(ev.key==='ArrowLeft'||ev.key==='ArrowUp')t=(i-1+n)%n;else if(ev.key==='Home')t=0;else if(ev.key==='End')t=n-1;
      if(t!==null){ev.preventDefault();select(t,true);history.replaceState(null,'','#'+panels[t].id);}});
  });
  const fromHash=()=>{const h=decodeURIComponent(location.hash.slice(1));if(!h)return;let i=panels.findIndex(p=>p.id===h);
    if(i<0){const el=document.getElementById(h);i=panels.findIndex(p=>p.contains(el));}
    if(i>=0)select(i,false);};
  fromHash();addEventListener('hashchange',fromHash);
}
})();
"""

BRAND_MARK = (
    '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round">'
    '<path d="M4 7.5 12 3l8 4.5v9L12 21l-8-4.5zM4 7.5l8 4.5 8-4.5M12 12v9"/></svg>'
)
COPY_ICON = (
    '<svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="1.5"/>'
    '<path d="M5 15V5a1 1 0 0 1 1-1h10"/></svg>'
    '<svg class="ok" viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7"/></svg>'
)
CHEVRON = '<svg class="chev" viewBox="0 0 24 24" aria-hidden="true"><path d="M9 6l6 6-6 6"/></svg>'
FOLDER_CLOSED = (
    '<svg class="ico folder closed" viewBox="0 0 24 24" aria-hidden="true">'
    '<path d="M3 7a2 2 0 0 1 2-2h4.2a2 2 0 0 1 1.4.6L12 7h7a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>'
)
FOLDER_OPEN = (
    '<svg class="ico folder open" viewBox="0 0 24 24" aria-hidden="true">'
    '<path d="M3 7a2 2 0 0 1 2-2h4.2a2 2 0 0 1 1.4.6L12 7h7a2 2 0 0 1 2 2v1H6.5a2 2 0 0 0-1.9 1.4L3 16z"/>'
    '<path d="M3 16l1.6-5.6A2 2 0 0 1 6.5 9H22l-2.2 8.5A2 2 0 0 1 17.9 19H5a2 2 0 0 1-2-2z"/></svg>'
)
FILE_ICON = (
    '<svg class="ico file" viewBox="0 0 24 24" aria-hidden="true">'
    '<path d="M6 3h8l5 5v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z"/><path d="M14 3v5h5"/></svg>'
)
GITHUB_ICON = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 .5A12 12 0 0 0 8.2 23.9c.6.1.8-.3.8-.6v-2.2c-3.3.7-4-1.4-4-1.4-.6-1.4-1.4-1.8-1.4-1.8-1.1-.7.1-.7.1-.7 1.2.1 1.8 1.2 1.8 1.2 1.1 1.8 2.8 1.3 3.5 1 .1-.8.4-1.3.8-1.6-2.7-.3-5.5-1.3-5.5-5.9 0-1.3.5-2.4 1.2-3.2-.1-.3-.5-1.5.1-3.2 0 0 1-.3 3.3 1.2a11.5 11.5 0 0 1 6 0c2.3-1.5 3.3-1.2 3.3-1.2.7 1.7.2 2.9.1 3.2.8.8 1.2 1.9 1.2 3.2 0 4.6-2.8 5.6-5.5 5.9.4.4.8 1.1.8 2.2v3.3c0 .3.2.7.8.6A12 12 0 0 0 12 .5z"/></svg>'
