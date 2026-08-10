"""Uploads are namespaced by schema.

``TenantFileSystemStorage`` resolves ``MEDIA_ROOT`` and ``MEDIA_URL`` through
``MULTITENANT_RELATIVE_MEDIA_ROOT`` on *every* access rather than caching them,
so the same ``default_storage`` object follows the connection from tenant to
tenant. Two institutions can therefore upload ``logo.png`` without either one
overwriting or reading the other's file.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from django.conf import settings
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django_tenants.files.storage import TenantFileSystemStorage
from django_tenants.utils import tenant_context

if TYPE_CHECKING:
    from apps.tenants.models import Tenant


@pytest.fixture
def storage_path() -> Path:
    return Path(settings.MEDIA_ROOT)


def storage_location() -> Path:
    """Directory ``default_storage`` writes to right now.

    Asserting on ``default_storage`` rather than a freshly built storage object
    is the point: it proves the *configured* backend is the tenant-aware one
    and that it re-resolves its location on every access.
    """
    assert isinstance(default_storage, TenantFileSystemStorage)
    return Path(default_storage.location)


@pytest.mark.django_db
class TestTenantMediaPaths:
    def test_storage_location_follows_the_active_tenant(
        self,
        acme: Tenant,
        beta: Tenant,
        storage_path: Path,
    ) -> None:
        with tenant_context(acme):
            acme_location = storage_location()
        with tenant_context(beta):
            beta_location = storage_location()

        assert acme_location == storage_path / "acme"
        assert beta_location == storage_path / "beta"

    def test_urls_are_namespaced_by_schema(self, acme: Tenant) -> None:
        with tenant_context(acme):
            url = default_storage.url("logo.png")

        assert url == "/media/acme/logo.png"

    def test_same_filename_in_two_tenants_does_not_collide(
        self,
        acme: Tenant,
        beta: Tenant,
        storage_path: Path,
    ) -> None:
        with tenant_context(acme):
            acme_name = default_storage.save("logo.png", ContentFile(b"acme-bytes"))
        with tenant_context(beta):
            beta_name = default_storage.save("logo.png", ContentFile(b"beta-bytes"))

        # Neither save was given a uniquifying suffix, because as far as each
        # tenant is concerned the directory was empty.
        assert acme_name == "logo.png"
        assert beta_name == "logo.png"

        assert (storage_path / "acme" / "logo.png").read_bytes() == b"acme-bytes"
        assert (storage_path / "beta" / "logo.png").read_bytes() == b"beta-bytes"

    def test_a_tenant_cannot_see_another_tenants_upload(
        self,
        acme: Tenant,
        beta: Tenant,
    ) -> None:
        with tenant_context(acme):
            default_storage.save("private.txt", ContentFile(b"secret"))

        with tenant_context(beta):
            assert not default_storage.exists("private.txt")

    def test_the_file_is_readable_from_its_own_tenant(
        self,
        acme: Tenant,
    ) -> None:
        with tenant_context(acme):
            default_storage.save("readable.txt", ContentFile(b"hello"))

            with default_storage.open("readable.txt") as handle:
                assert handle.read() == b"hello"

    def test_public_schema_uploads_land_under_public(
        self,
        public_tenant: Tenant,
        storage_path: Path,
    ) -> None:
        default_storage.save("brochure.pdf", ContentFile(b"platform"))

        assert (storage_path / "public" / "brochure.pdf").exists()
