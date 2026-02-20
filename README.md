# Keycloak IdP Attribute Linker SPI

[English](#english) | [ภาษาไทย](#thai)

---

<a name="english"></a>
## English Description

**Keycloak IdP Attribute Linker** is a generic Service Provider Interface (SPI) for Keycloak 26+. It provides a secure, privacy-focused way to link external Identity Provider (IdP) users to existing local Keycloak users using multiple custom attributes.

### Key Features
* **Multi-Attribute Matching (AND Logic)**: Link users by matching multiple fields simultaneously. All specified rules must pass to identify a user.
* **Dynamic Configuration**: Configure matching rules, attribute names, and salt directly from the Keycloak Admin UI.
* **Privacy-by-Design (PDPA)**: Includes an Identity Provider Mapper that hashes the IdP Subject ID (sub) using SHA-256 with Salt before storing it in the database.
* **Optional Hashing**: Choose whether to hash individual attributes (e.g., hash National ID, but keep Email in plain text) for matching.
* **Full Localization Support**: Customize error messages in any language using Keycloak's theme resources.

---

<a name="thai"></a>
## รายละเอียดภาษาไทย

**Keycloak IdP Attribute Linker** คือ SPI สำหรับ Keycloak 26+ ที่ออกแบบมาเพื่อเชื่อมต่อบัญชีระหว่าง Identity Provider ภายนอก กับบัญชีใน Keycloak โดยอัตโนมัติผ่านการตรวจสอบหลายเงื่อนไขพร้อมกันอย่างปลอดภัย

### คุณสมบัติหลัก
* **Multi-Attribute Matching (AND Logic)**: รองรับการจับคู่ผ่านหลาย Attribute พร้อมกัน โดยผู้ใช้งานต้องมีข้อมูลตรงกับทุกเงื่อนไขที่กำหนดเท่านั้น
* **Dynamic Configuration**: ตั้งค่ากฎการจับคู่, ชื่อ Attribute และค่า Salt ได้โดยตรงผ่านหน้าจอ Admin UI
* **Privacy-by-Design (PDPA)**: มาพร้อม Mapper ที่ทำหน้าที่ Hash ค่า Subject ID (sub) ด้วย SHA-256 และ Salt ก่อนบันทึกลงฐานข้อมูล เพื่อป้องกันข้อมูลส่วนบุคคลรั่วไหล
* **Optional Hashing**: เลือกทำ Hash ข้อมูลแยกตามฟิลด์ได้ (เช่น ทำ Hash เลขบัตรประชาชน แต่ไม่ทำ Hash อีเมล์) สำหรับการจับคู่
* **Full Localization Support**: รองรับการปรับแต่งข้อความแจ้งเตือน (Error Messages) ผ่านระบบ Theme ของ Keycloak

---

## ⚙️ Configuration (การตั้งค่า)

### 1. Identity Provider Mapper (Privacy Hashing)
To protect privacy in the `FEDERATED_IDENTITY` table:
* Go to **Identity Providers** > Select your Provider.
* Go to **Mappers** tab > **Add Mapper**.
* Select **Mapper Type**: `IdP ID Privacy Hasher`.
* **Hash Salt**: Enter a secret string. *Must be the same as in the Authenticator.*

### 2. Authentication Flow (Auto-Linking)
To enable automatic matching:
* Go to **Authentication** > Duplicate **First Broker Login** flow.
* Add a new step: **IdP Attribute Match Authenticator (Multi-Field)**.
* Set it to **REQUIRED**.
* Click the **Settings (Gear icon)**:
    * **Matching Rules**: Format `idp_attr:user_attr:hash`. Example: `citizen_id:cid:true, email:email`.
    * **Hash Salt**: Enter the same secret string used in the Mapper.

### 3. Localization (Customizing Messages)
To customize error messages, add these keys to your Keycloak theme's `messages/messages_xx.properties`:

| Message Key | Default English Meaning |
| :--- | :--- |
| `idp-linker-no-user-found` | No user found matching the requirements. |
| `idp-linker-data-mismatch` | Identity data does not match our records. |
| `idp-linker-multiple-users-found` | Multiple users found with the same identity. |

---

## 🛠 Installation (การติดตั้ง)

1. **Build the project**: `mvn clean package`
2. **Deploy**: Copy the `.jar` from `target/` to Keycloak `providers/` directory.
3. **Optimize & Restart**: `bin/kc.sh build` then `bin/kc.sh start`

---

## 🔒 Security & Environment Variables
For production, you can set the Salt via an environment variable instead of the UI:
```bash
export IDP_LINKER_HASH_SALT="YourVeryLongSecretSalt"