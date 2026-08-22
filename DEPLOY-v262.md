# S-RECO dedicated compute v262

## Akar yang diperbaiki

Data yang tersedia membuktikan target aplikasi tidak sempat mengirim status diagnostik 549–558: invocation berakhir sekitar 57–69 detik ketika RSS mencapai sekitar 1.235 GB, lalu platform menampilkan 503. Pola ini menunjukkan penghentian pada lapisan runtime/compute sebelum blok `catch` selesai. Data tersebut saja tidak dapat membedakan secara mutlak antara batas durasi plan dan hard resource termination; keduanya diperbaiki oleh target compute ini. Pada revisi v276, S-RECO mengunci setiap Argon2id recovery pada `memoryCost` 512.000 KiB (500 MiB).

Patch v262 tidak mengubah `api/health.js`, `vercel.json`, S-UTAMA, Central Guard, parameter Argon2id, signature, persistent ban, key separation, maupun kriptografi. Patch hanya menambahkan runtime container dengan sumber daya yang cukup dan tanpa batas eksekusi serverless satu menit.

## Syarat deployment wajib

1. Deploy direktori `S-RECO` sebagai container dari `Dockerfile`, bukan sebagai Vercel Function.
2. Sediakan hard limit minimum 8 GiB RAM dan sedikitnya 4 vCPU yang terjamin/tidak di-throttle. Jangan menurunkan parameter Argon2id di bawah 512.000 KiB.
3. Salin environment production S-RECO yang sekarang ke secret manager target secara persis. Jangan masukkan environment yang secara eksplisit dilarang oleh pemisahan Server 1/Server 2.
4. Pertahankan `DIRAC_CENTRAL_DEPLOYMENT_ROLE=vercel2` dan flag S-RECO yang diwajibkan kode. Kata `vercel2` adalah nilai role keamanan; itu tidak mewajibkan runtime Vercel.
5. Ekspos container hanya melalui reverse proxy HTTPS untuk `secure.diracgroup.store`. Port 3000 tetap private/loopback.
6. Reverse proxy harus menimpa header dari klien, lalu menetapkan `Host`/`X-Forwarded-Host` ke `secure.diracgroup.store` dan `X-Forwarded-Proto` ke `https`. Jangan mengubah body atau header `X-Dirac-*` yang ditandatangani.
7. Atur timeout proxy/ingress sekurangnya 300 detik dan graceful termination sekurangnya 300 detik. S-UTAMA sudah membatasi panggilan worker hingga maksimum 290 detik.
8. Setelah HTTPS sehat, arahkan DNS `secure.diracgroup.store` ke ingress container. Nilai URL worker di S-UTAMA tetap `https://secure.diracgroup.store/api/health`.

`compose.yaml` menerapkan 8 GiB RAM, 4 vCPU, non-root user, read-only filesystem, seluruh Linux capability dihapus, `no-new-privileges`, port loopback, dan grace period lima menit. Buat `S-RECO/.env.production` hanya pada host deployment; file secret itu sengaja tidak ada dan dikecualikan dari image serta Git.

Jangan menguji endpoint dengan `curl` atau request tanpa signature. Central Guard bersifat fail-closed dan dapat membuat persistent ban. Verifikasi end-to-end hanya melalui flow S-UTAMA yang menghasilkan envelope dan tujuh signature sah.
