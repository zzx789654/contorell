"""網頁路由 — 實作 docs/UX-Design.md 的六步流程。

UX 決策：首頁即「新增比對」（核心動作路徑最短），
設定類功能收在次要導覽，不擋在主流程上。
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import desc, select

from app.auth.service import AuthenticationFailed, AuthService
from app.comparison.engine import MatchStatus, RiskLevel, compare
from app.db.models import (
    Annotation,
    Comparison,
    ComparisonRowRecord,
    CustomFieldDefinition,
    DataSource,
    Snapshot,
    SourceType,
)
from app.export.excel import build_filename, export_to_csv, export_to_excel
from app.providers.base import Account, AccountStatus, FetchResult, ProviderError
from app.providers.ldap_provider import LdapProvider, NestingStrategy
from app.providers.ldap_queries import (
    DEFAULT_TEMPLATE_KEY,
    OPTIONAL_ATTRIBUTES,
    QUERY_TEMPLATES,
    SearchScope,
)
from app.security.csrf import get_or_create_token, rotate_token
from app.web.deps import (
    AdminUser,
    CsrfProtected,
    CurrentUser,
    LdapConfigDep,
    SessionDep,
    client_ip,
    record_audit,
)
from app.web.services import (
    build_provider,
    build_review,
    create_manual_entitlement,
    encrypt_secret,
    entitlement_detail,
    store_snapshot,
    upsert_entitlement_note,
)
from app.web.source_forms import (
    FormValidationError,
    config_to_form_values,
    parse_ldap_form,
)
from app.web.templates import templates

logger = logging.getLogger(__name__)
router = APIRouter()

PAGE_SIZE = 50


# ---------------------------------------------------------------------------
# 認證
# ---------------------------------------------------------------------------


@router.get("/login")
async def login_page(request: Request) -> Response:
    if request.session.get("user_id"):
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    # 先建立 CSRF token，讓登入表單能帶上（防止登入型 CSRF）。
    # token 由模板全域函式 csrf_token(request) 取用，此處只負責確保已產生。
    get_or_create_token(request)
    return templates.TemplateResponse(request, "login.html", {"request": request})


@router.post("/login", dependencies=[CsrfProtected])
async def login_submit(
    request: Request,
    session: SessionDep,
    ldap_config: LdapConfigDep,
    username: str = Form(...),
    password: str = Form(...),
) -> Response:
    service = AuthService(session, ldap_config)

    try:
        result = service.authenticate(username, password, ip_address=client_ip(request))
    except AuthenticationFailed as exc:
        # 失敗訊息一律通用，不透露帳號是否存在（AC-13b）
        return templates.TemplateResponse(
            request,
            "login.html",
            {"request": request, "error": exc.message, "username": username},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    # 防 session fixation：登入成功後換發 session 與 CSRF token
    request.session.clear()
    request.session["user_id"] = result.user.id
    request.session["auth_method"] = result.method
    rotate_token(request)

    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/logout", dependencies=[CsrfProtected])
async def logout(request: Request) -> Response:
    request.session.clear()
    return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)


# ---------------------------------------------------------------------------
# 首頁：新增比對（核心動作）
# ---------------------------------------------------------------------------


@router.get("/")
async def home(request: Request, session: SessionDep, user: CurrentUser) -> Response:
    sources = session.scalars(
        select(DataSource).where(DataSource.is_active).order_by(DataSource.name)
    ).all()

    recent = session.scalars(
        select(Comparison).order_by(desc(Comparison.compared_at)).limit(10)
    ).all()

    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "request": request,
            "user": user,
            "sources": sources,
            "recent_comparisons": recent,
        },
    )


@router.get("/review")
async def access_review_page(request: Request, session: SessionDep, user: CurrentUser) -> Response:
    """權限檢視主畫面（Round 8）：AD 已啟用人員 × 各權限群組矩陣 + 異常。

    以權威來源（AD）的最新快照為主檔，其餘啟用來源為權限群組。
    尚未設定權威主檔或主檔無快照時，``review`` 為 None，由模板顯示引導。
    """
    review = build_review(session)
    master_source = session.scalars(
        select(DataSource).where(DataSource.is_active, DataSource.is_authoritative).limit(1)
    ).first()
    # 權限群組名稱 → 來源 id，供矩陣連到各自的分頁
    entitlement_links = {
        s.name: s.id
        for s in session.scalars(
            select(DataSource).where(DataSource.is_active, DataSource.is_authoritative.is_(False))
        )
    }
    return templates.TemplateResponse(
        request,
        "review.html",
        {
            "request": request,
            "user": user,
            "active_nav": "review",
            "review": review,
            "master_source": master_source,
            "entitlement_links": entitlement_links,
        },
    )


@router.get("/review/source/{source_id}")
async def entitlement_detail_page(
    request: Request, session: SessionDep, user: CurrentUser, source_id: int
) -> Response:
    """權限來源分頁（Round 8，規格第 6 點）：列出該來源成員、狀態、異常與註記。"""
    detail = entitlement_detail(session, source_id)
    if detail is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "找不到此權限來源。")
    return templates.TemplateResponse(
        request,
        "entitlement_detail.html",
        {
            "request": request,
            "user": user,
            "active_nav": "review",
            "detail": detail,
        },
    )


@router.get("/review/manual")
async def manual_entitlement_form(request: Request, user: AdminUser) -> Response:
    """手動 KEY-IN 權限名單的建立表單（管理者）。"""
    return templates.TemplateResponse(
        request,
        "manual_entitlement.html",
        {"request": request, "user": user, "active_nav": "review"},
    )


@router.post("/review/manual", dependencies=[CsrfProtected])
async def manual_entitlement_create(
    request: Request,
    session: SessionDep,
    user: AdminUser,
    name: str = Form(...),
    account_ids: str = Form(""),
) -> Response:
    """建立手動 KEY-IN 權限來源（規格第 5 點）。"""
    if not name.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "請填寫權限名稱。")

    source = create_manual_entitlement(session, name, account_ids, user.username)
    record_audit(
        session,
        user,
        "manual_entitlement_create",
        target_type="data_source",
        target_id=str(source.id),
        detail=f"手動建立權限來源「{source.name}」",
        ip_address=client_ip(request),
    )
    session.commit()
    return RedirectResponse(f"/review/source/{source.id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/review/source/{source_id}/note", dependencies=[CsrfProtected])
async def save_entitlement_note(
    request: Request,
    session: SessionDep,
    user: AdminUser,
    source_id: int,
    account_key: str = Form(...),
    note: str = Form(""),
) -> Response:
    """儲存某成員的自訂註記（管理者）。"""
    detail = entitlement_detail(session, source_id)
    if detail is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "找不到此權限來源。")

    upsert_entitlement_note(
        session, source_id, account_key.strip().lower(), note.strip(), user.username
    )
    record_audit(
        session,
        user,
        "entitlement_note",
        target_type="data_source",
        target_id=str(source_id),
        detail=f"帳號 {account_key} 註記已更新",
        ip_address=client_ip(request),
    )
    session.commit()
    return RedirectResponse(f"/review/source/{source_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/compare", dependencies=[CsrfProtected])
async def run_comparison(
    request: Request,
    session: SessionDep,
    user: AdminUser,
    source_a_id: int = Form(...),
    source_b_id: int = Form(...),
) -> Response:
    """執行比對（FR-06）—— 六步流程的第 3 步，核心動作。"""
    if source_a_id == source_b_id:
        raise HTTPException(400, "來源 A 與來源 B 不可相同。請選擇兩個不同的資料來源。")

    source_a = _get_source(session, source_a_id)
    source_b = _get_source(session, source_b_id)

    # 抓取並保存快照（FR-11）
    result_a = _fetch_and_store(session, source_a, user, request)
    result_b = _fetch_and_store(session, source_b, user, request)

    comparison_result = compare(
        result_a.fetch_result,
        result_b.fetch_result,
        a_is_authoritative=source_a.is_authoritative,
    )

    record = Comparison(
        name=f"{source_a.name} vs {source_b.name}",
        snapshot_a_id=result_a.snapshot.id,
        snapshot_b_id=result_b.snapshot.id,
        compared_by=user.username,
        source_a_label=comparison_result.summary.source_a_label,
        source_b_label=comparison_result.summary.source_b_label,
        source_a_count=comparison_result.summary.source_a_count,
        source_b_count=comparison_result.summary.source_b_count,
        status_counts_json={
            key.value: count for key, count in comparison_result.summary.status_counts.items()
        },
        risk_counts_json={
            key.value: count for key, count in comparison_result.summary.risk_counts.items()
        },
        warnings_json=comparison_result.summary.warnings,
    )
    session.add(record)
    session.flush()

    for row in comparison_result.rows:
        session.add(
            ComparisonRowRecord(
                comparison_id=record.id,
                account_key=row.key,
                display_identifier=row.display_identifier,
                display_name=row.display_name,
                match_status=row.status.value,
                risk_level=row.risk.value,
                risk_reason=row.risk_reason,
                differences_json=row.differences,
                account_a_json=_account_to_json(row.account_a),
                account_b_json=_account_to_json(row.account_b),
            )
        )

    record_audit(
        session,
        user,
        "comparison_run",
        target_type="comparison",
        target_id=str(record.id),
        detail=f"{source_a.name} vs {source_b.name}，共 {len(comparison_result.rows)} 筆",
        ip_address=client_ip(request),
    )
    session.commit()

    return RedirectResponse(f"/comparisons/{record.id}", status_code=status.HTTP_303_SEE_OTHER)


# ---------------------------------------------------------------------------
# 比對結果檢視與標註
# ---------------------------------------------------------------------------


@router.get("/comparisons/{comparison_id}")
async def view_comparison(
    request: Request,
    session: SessionDep,
    user: CurrentUser,
    comparison_id: int,
    status_filter: str = "",
    risk_filter: str = "",
    q: str = "",
    page: int = 1,
) -> Response:
    comparison = session.get(Comparison, comparison_id)
    if comparison is None:
        raise HTTPException(404, "找不到指定的比對紀錄。")

    query = select(ComparisonRowRecord).where(ComparisonRowRecord.comparison_id == comparison_id)
    if status_filter:
        query = query.where(ComparisonRowRecord.match_status == status_filter)
    if risk_filter:
        query = query.where(ComparisonRowRecord.risk_level == risk_filter)
    if q:
        # 參數化查詢，不拼接 SQL
        pattern = f"%{q.strip()}%"
        query = query.where(ComparisonRowRecord.display_identifier.ilike(pattern))

    all_rows = session.scalars(query).all()
    # 高風險優先（UX 決策）
    order = {RiskLevel.HIGH.value: 0, RiskLevel.MEDIUM.value: 1, RiskLevel.LOW.value: 2}
    sorted_rows = sorted(all_rows, key=lambda r: (order.get(r.risk_level, 3), r.account_key))

    page = max(1, page)
    start = (page - 1) * PAGE_SIZE
    rows = sorted_rows[start : start + PAGE_SIZE]

    custom_fields = session.scalars(
        select(CustomFieldDefinition)
        .where(CustomFieldDefinition.is_active)
        .order_by(CustomFieldDefinition.display_order)
    ).all()

    annotations = _load_annotations(session, [row.id for row in rows])

    context = {
        "request": request,
        "user": user,
        "comparison": comparison,
        "rows": rows,
        "custom_fields": custom_fields,
        "annotations": annotations,
        "status_filter": status_filter,
        "risk_filter": risk_filter,
        "q": q,
        "page": page,
        "total_rows": len(sorted_rows),
        "total_pages": max(1, (len(sorted_rows) + PAGE_SIZE - 1) // PAGE_SIZE),
        "match_statuses": list(MatchStatus),
        "risk_levels": list(RiskLevel),
    }

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "partials/result_table.html", context)
    return templates.TemplateResponse(request, "comparison_detail.html", context)


@router.post("/rows/{row_id}/annotate", dependencies=[CsrfProtected])
async def save_annotation(
    request: Request,
    session: SessionDep,
    user: AdminUser,
    row_id: int,
    field_key: str = Form(...),
    value: str = Form(""),
) -> Response:
    """就地儲存自訂欄位（FR-09、AC-09）。"""
    row = session.get(ComparisonRowRecord, row_id)
    if row is None:
        raise HTTPException(404, "找不到指定的比對結果列。")

    field = session.scalar(
        select(CustomFieldDefinition).where(CustomFieldDefinition.key == field_key)
    )
    if field is None or not field.is_active:
        raise HTTPException(400, f"欄位「{field_key}」不存在或已停用。")

    annotation = session.scalar(
        select(Annotation).where(Annotation.row_id == row_id, Annotation.field_key == field_key)
    )
    if annotation is None:
        annotation = Annotation(row_id=row_id, field_key=field_key)
        session.add(annotation)

    annotation.value = value.strip()
    annotation.updated_by = user.username

    record_audit(
        session,
        user,
        "annotation_saved",
        target_type="comparison_row",
        target_id=str(row_id),
        detail=f"{field_key}={value[:100]}",
        ip_address=client_ip(request),
    )
    session.commit()

    return templates.TemplateResponse(
        request,
        "partials/annotation_saved.html",
        {"request": request, "value": annotation.value, "field": field, "row_id": row_id},
    )


# ---------------------------------------------------------------------------
# 匯出
# ---------------------------------------------------------------------------


@router.get("/comparisons/{comparison_id}/export")
async def export_comparison(
    request: Request,
    session: SessionDep,
    user: CurrentUser,
    comparison_id: int,
    fmt: str = "xlsx",
) -> Response:
    """匯出比對結果（FR-12、AC-12）。"""
    if fmt not in ("xlsx", "csv"):
        raise HTTPException(400, "不支援的匯出格式，請選擇 xlsx 或 csv。")

    comparison = session.get(Comparison, comparison_id)
    if comparison is None:
        raise HTTPException(404, "找不到指定的比對紀錄。")

    result = _rebuild_comparison_result(session, comparison)

    fields = session.scalars(
        select(CustomFieldDefinition)
        .where(CustomFieldDefinition.is_active)
        .order_by(CustomFieldDefinition.display_order)
    ).all()

    values = _load_annotations_by_key(session, comparison_id, [f.key for f in fields])

    if fmt == "xlsx":
        content = export_to_excel(
            result,
            custom_field_labels=[f.label for f in fields],
            custom_field_values=values,
        )
        media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    else:
        content = export_to_csv(
            result,
            custom_field_labels=[f.label for f in fields],
            custom_field_values=values,
        )
        media_type = "text/csv; charset=utf-8"

    record_audit(
        session,
        user,
        "comparison_exported",
        target_type="comparison",
        target_id=str(comparison_id),
        detail=f"format={fmt}",
        ip_address=client_ip(request),
    )
    session.commit()

    filename = build_filename(result, fmt)
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# 資料來源設定
# ---------------------------------------------------------------------------


@router.get("/sources")
async def list_sources(request: Request, session: SessionDep, user: CurrentUser) -> Response:
    sources = session.scalars(select(DataSource).order_by(DataSource.name)).all()
    return templates.TemplateResponse(
        request,
        "sources.html",
        {"request": request, "user": user, "sources": sources, "source_types": list(SourceType)},
    )


@router.get("/sources/new")
async def new_source_form(request: Request, user: AdminUser) -> Response:
    """新增 AD／LDAP 來源的設定表單。"""
    return templates.TemplateResponse(
        request,
        "source_form.html",
        {
            "request": request,
            "user": user,
            "source": None,
            "values": _default_form_values(),
            "errors": {},
            **_form_reference_data(),
        },
    )


@router.get("/sources/{source_id}/edit")
async def edit_source_form(
    request: Request, session: SessionDep, user: AdminUser, source_id: int
) -> Response:
    """編輯既有來源。密碼不回填——密文無法還原，且不應送回瀏覽器。"""
    source = session.get(DataSource, source_id)
    if source is None:
        raise HTTPException(404, "找不到指定的資料來源。")
    if source.source_type != SourceType.LDAP.value:
        raise HTTPException(400, "目前僅支援在網頁上編輯 AD／LDAP 來源的設定。")

    values = config_to_form_values(source.config_json or {})
    values.update(
        {
            "name": source.name,
            "description": source.description,
            "is_authoritative": source.is_authoritative,
            "is_active": source.is_active,
        }
    )

    return templates.TemplateResponse(
        request,
        "source_form.html",
        {
            "request": request,
            "user": user,
            "source": source,
            "values": values,
            "errors": {},
            **_form_reference_data(),
        },
    )


@router.post("/sources/save", dependencies=[CsrfProtected])
async def save_source(
    request: Request, session: SessionDep, user: AdminUser, source_id: int = Form(0)
) -> Response:
    """新增或更新 AD／LDAP 來源設定。

    驗證失敗時把使用者填的值原樣回填（除了密碼），
    讓管理者不必重打整份表單——只改有問題的欄位即可。
    """
    form = await request.form()
    raw: dict[str, str] = {
        key: str(value) for key, value in form.items() if not hasattr(value, "filename")
    }
    # 屬性是多選 checkbox，form.items() 只會留下最後一個值，
    # 必須用 getlist 取完整清單再合併成表單層認得的格式。
    raw["extra_attributes"] = ",".join(form.getlist("extra_attributes"))

    existing = session.get(DataSource, source_id) if source_id else None
    if source_id and existing is None:
        raise HTTPException(404, "找不到要編輯的資料來源。")

    try:
        parsed = parse_ldap_form(raw, is_edit=existing is not None)
    except FormValidationError as exc:
        values = dict(raw)
        values.pop("bind_password", None)
        values["extra_attributes"] = [
            a.strip() for a in (raw.get("extra_attributes") or "").split(",") if a.strip()
        ]
        return templates.TemplateResponse(
            request,
            "source_form.html",
            {
                "request": request,
                "user": user,
                "source": existing,
                "values": values,
                "errors": exc.errors,
                **_form_reference_data(),
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # 名稱唯一性由資料庫約束保證，這裡先查一次以給出友善訊息
    duplicate = session.scalar(
        select(DataSource).where(
            DataSource.name == parsed.name,
            DataSource.id != (existing.id if existing else 0),
        )
    )
    if duplicate is not None:
        return templates.TemplateResponse(
            request,
            "source_form.html",
            {
                "request": request,
                "user": user,
                "source": existing,
                "values": dict(raw),
                "errors": {"name": f"已經有一個叫「{parsed.name}」的來源了，請換個名稱。"},
                **_form_reference_data(),
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if existing is None:
        existing = DataSource(source_type=SourceType.LDAP.value, created_by=user.username)
        session.add(existing)
        action = "source_created"
    else:
        action = "source_updated"

    existing.name = parsed.name
    existing.description = parsed.description
    existing.is_authoritative = parsed.is_authoritative
    existing.is_active = parsed.is_active
    existing.config_json = parsed.to_config_json()

    # 密碼留空代表沿用原本的（編輯情境），不覆寫成空字串
    if parsed.bind_password is not None:
        existing.encrypted_secret = encrypt_secret(parsed.bind_password)

    session.flush()

    record_audit(
        session,
        user,
        action,
        target_type="data_source",
        target_id=str(existing.id),
        # 稽核紀錄只留設定摘要，絕不記錄密碼
        detail=f"{parsed.name}｜{parsed.host}:{parsed.port}｜範本={parsed.template_key or '群組成員'}",
        ip_address=client_ip(request),
    )
    session.commit()

    return RedirectResponse("/sources", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/sources/{source_id}/toggle", dependencies=[CsrfProtected])
async def toggle_source(
    request: Request, session: SessionDep, user: AdminUser, source_id: int
) -> Response:
    """啟用／停用來源。

    刻意不提供刪除——快照與比對紀錄會參照來源，
    刪除會讓既有的稽核紀錄失去脈絡（Comparison 的外鍵是 RESTRICT）。
    """
    source = session.get(DataSource, source_id)
    if source is None:
        raise HTTPException(404, "找不到指定的資料來源。")

    source.is_active = not source.is_active

    record_audit(
        session,
        user,
        "source_toggled",
        target_type="data_source",
        target_id=str(source_id),
        detail="啟用" if source.is_active else "停用",
        ip_address=client_ip(request),
    )
    session.commit()

    return RedirectResponse("/sources", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/sources/{source_id}/groups", dependencies=[CsrfProtected])
async def lookup_user_groups(
    request: Request,
    session: SessionDep,
    user: AdminUser,
    source_id: int,
    account: str = Form(""),
) -> Response:
    """反查某帳號隸屬於哪些群組（含巢狀）。

    這是設定頁的診斷工具——用來確認群組 DN 是否填對、
    以及某個人為什麼會出現在比對結果裡。
    """
    source = _get_source(session, source_id)
    provider = build_provider(source)

    if not isinstance(provider, LdapProvider):
        raise HTTPException(400, "只有 AD／LDAP 來源支援群組反查。")

    try:
        result = provider.find_user_groups(account)
    except ProviderError as exc:
        return templates.TemplateResponse(
            request,
            "partials/user_groups.html",
            {"request": request, "error": exc, "account": account},
            status_code=status.HTTP_502_BAD_GATEWAY,
        )

    record_audit(
        session,
        user,
        "user_groups_looked_up",
        target_type="data_source",
        target_id=str(source_id),
        detail=f"查詢帳號 {account[:100]}",
        ip_address=client_ip(request),
    )
    session.commit()

    return templates.TemplateResponse(
        request,
        "partials/user_groups.html",
        {"request": request, "result": result, "account": account},
    )


@router.post("/sources/{source_id}/test", dependencies=[CsrfProtected])
async def test_source(
    request: Request, session: SessionDep, user: AdminUser, source_id: int
) -> Response:
    """測試連線並顯示診斷資訊（AC-01、IR-07）。"""
    source = _get_source(session, source_id)
    provider = build_provider(source)

    try:
        diagnostics = provider.test_connection()
    except ProviderError as exc:
        return templates.TemplateResponse(
            request,
            "partials/diagnostics.html",
            {"request": request, "error": exc, "source": source, "diagnostics": {}},
            status_code=status.HTTP_502_BAD_GATEWAY,
        )

    record_audit(
        session,
        user,
        "source_tested",
        target_type="data_source",
        target_id=str(source_id),
        ip_address=client_ip(request),
    )
    session.commit()

    return templates.TemplateResponse(
        request,
        "partials/diagnostics.html",
        {"request": request, "diagnostics": diagnostics, "source": source},
    )


@router.get("/audit")
async def audit_log(request: Request, session: SessionDep, user: CurrentUser) -> Response:
    """稽核軌跡（FR-14）—— P2 稽核者的主要入口。"""
    from app.db.models import AuditLog

    logs = session.scalars(select(AuditLog).order_by(desc(AuditLog.occurred_at)).limit(200)).all()

    return templates.TemplateResponse(
        request, "audit.html", {"request": request, "user": user, "logs": logs}
    )


# ---------------------------------------------------------------------------
# 內部輔助
# ---------------------------------------------------------------------------


def _form_reference_data() -> dict:
    """設定表單需要的選項清單與說明資料。

    集中在這裡，讓三個會渲染表單的路由（新增／編輯／驗證失敗回填）
    不會各自組一份而漸漸不一致。
    """
    return {
        "query_templates": QUERY_TEMPLATES,
        "attribute_options": OPTIONAL_ATTRIBUTES,
        "nesting_strategies": list(NestingStrategy),
        "search_scopes": list(SearchScope),
    }


def _default_form_values() -> dict:
    """新增來源時的預設值 —— 一律採安全預設（LDAPS + 驗憑證）。"""
    return {
        "port": 636,
        "use_ssl": True,
        "use_start_tls": False,
        "verify_cert": True,
        "is_active": True,
        "is_authoritative": True,
        "template_key": DEFAULT_TEMPLATE_KEY,
        "nesting_strategy": NestingStrategy.RECURSIVE.value,
        "search_scope": SearchScope.SUBTREE.value,
        "page_size": 1000,
        "receive_timeout": 30,
        "extra_attributes": [],
    }


def _get_source(session, source_id: int) -> DataSource:  # type: ignore[no-untyped-def]
    source = session.get(DataSource, source_id)
    if source is None or not source.is_active:
        raise HTTPException(404, "找不到指定的資料來源，或該來源已停用。")
    return source


class _FetchOutcome:
    def __init__(self, snapshot: Snapshot, fetch_result: FetchResult) -> None:
        self.snapshot = snapshot
        self.fetch_result = fetch_result


def _fetch_and_store(session, source: DataSource, user, request) -> _FetchOutcome:  # type: ignore[no-untyped-def]
    provider = build_provider(source)
    fetch_result = provider.fetch()
    snapshot = store_snapshot(session, source, fetch_result, user.username)

    record_audit(
        session,
        user,
        "source_fetched",
        target_type="data_source",
        target_id=str(source.id),
        detail=f"取得 {fetch_result.count} 筆帳號",
        ip_address=client_ip(request),
    )
    return _FetchOutcome(snapshot, fetch_result)


def _account_to_json(account: Account | None) -> dict | None:
    if account is None:
        return None
    return {
        "identifier": account.identifier,
        "display_name": account.display_name,
        "email": account.email,
        "status": account.status.value,
        "attributes": account.attributes,
    }


def _json_to_account(data: dict | None) -> Account | None:
    if not data:
        return None
    return Account(
        identifier=data["identifier"],
        display_name=data.get("display_name", ""),
        email=data.get("email", ""),
        status=AccountStatus(data.get("status", "unknown")),
        attributes=data.get("attributes", {}),
    )


def _rebuild_comparison_result(session, comparison: Comparison):  # type: ignore[no-untyped-def]
    """從資料庫重建比對結果供匯出使用。"""
    from app.comparison.engine import ComparisonResult, ComparisonRow, ComparisonSummary

    rows_records = session.scalars(
        select(ComparisonRowRecord).where(ComparisonRowRecord.comparison_id == comparison.id)
    ).all()

    rows = [
        ComparisonRow(
            key=record.account_key,
            status=MatchStatus(record.match_status),
            risk=RiskLevel(record.risk_level),
            risk_reason=record.risk_reason,
            account_a=_json_to_account(record.account_a_json),
            account_b=_json_to_account(record.account_b_json),
            differences=record.differences_json or [],
        )
        for record in rows_records
    ]
    rows.sort(key=lambda row: (row.risk.sort_order, row.key))

    summary = ComparisonSummary(
        source_a_label=comparison.source_a_label,
        source_b_label=comparison.source_b_label,
        source_a_count=comparison.source_a_count,
        source_b_count=comparison.source_b_count,
        status_counts={
            status: (comparison.status_counts_json or {}).get(status.value, 0)
            for status in MatchStatus
        },
        risk_counts={
            risk: (comparison.risk_counts_json or {}).get(risk.value, 0) for risk in RiskLevel
        },
        compared_at=comparison.compared_at,
        warnings=comparison.warnings_json or [],
    )

    return ComparisonResult(summary=summary, rows=rows)


def _load_annotations(session, row_ids: list[int]) -> dict[int, dict[str, str]]:  # type: ignore[no-untyped-def]
    if not row_ids:
        return {}
    records = session.scalars(select(Annotation).where(Annotation.row_id.in_(row_ids))).all()
    result: dict[int, dict[str, str]] = {}
    for record in records:
        result.setdefault(record.row_id, {})[record.field_key] = record.value
    return result


def _load_annotations_by_key(
    session, comparison_id: int, field_keys: list[str]
) -> dict[str, dict[str, str]]:  # type: ignore[no-untyped-def]
    """以 account_key 為索引取出標註，供匯出對齊。"""
    records = session.execute(
        select(ComparisonRowRecord.account_key, Annotation.field_key, Annotation.value)
        .join(Annotation, Annotation.row_id == ComparisonRowRecord.id)
        .where(ComparisonRowRecord.comparison_id == comparison_id)
    ).all()

    result: dict[str, dict[str, str]] = {}
    for account_key, field_key, value in records:
        result.setdefault(account_key, {})[field_key] = value

    # 補齊缺漏欄位，確保匯出時每列的欄位順序一致
    for values in result.values():
        for key in field_keys:
            values.setdefault(key, "")

    return {key: {k: values.get(k, "") for k in field_keys} for key, values in result.items()}
