"""
Health check endpoints for diagnosing service dependencies.
"""
import asyncio
import os
import shutil
import tempfile
import time
import subprocess
from fastapi import APIRouter

router = APIRouter(
    prefix="/health",
    tags=["health"],
)


@router.get("/libreoffice")
async def health_check_libreoffice():
    """
    Health check endpoint that verifies LibreOffice is installed and working.
    Useful for diagnosing conversion issues.
    """
    result = {
        "soffice_in_path": False,
        "soffice_path": None,
        "soffice_version": None,
        "soffice_executable": False,
        "error": None,
    }

    try:
        # Check if soffice is in PATH
        soffice_path = shutil.which("soffice")
        result["soffice_in_path"] = soffice_path is not None
        result["soffice_path"] = soffice_path

        if not soffice_path:
            common_paths = [
                "/usr/bin/soffice",
                "/usr/lib/libreoffice/program/soffice",
                "/opt/libreoffice/program/soffice",
            ]
            for path in common_paths:
                if os.path.exists(path):
                    result["soffice_path"] = path
                    break

        if result["soffice_path"]:
            try:
                proc = await asyncio.create_subprocess_exec(
                    result["soffice_path"], "--version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)

                if proc.returncode == 0:
                    result["soffice_version"] = stdout.decode().strip()
                    result["soffice_executable"] = True
                else:
                    result["error"] = f"Version check failed: {stderr.decode()}"
            except asyncio.TimeoutError:
                result["error"] = "Version check timed out (10s)"
            except FileNotFoundError as e:
                result["error"] = f"FileNotFoundError: {e}"
            except PermissionError as e:
                result["error"] = f"PermissionError: {e}"
        else:
            result["error"] = "soffice not found in PATH or common locations"

        if result["soffice_executable"]:
            return {"status": "healthy", "libreoffice": result}
        else:
            return {"status": "unhealthy", "libreoffice": result}

    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"
        return {"status": "error", "libreoffice": result}


@router.get("/libreoffice/test-conversion")
async def test_libreoffice_conversion():
    """
    Test LibreOffice conversion by creating a simple text file and converting it to PDF.
    This endpoint helps diagnose conversion issues.
    """
    start_time = time.time()
    test_result = {
        "success": False,
        "duration_seconds": 0,
        "steps": [],
        "error": None,
    }

    temp_dir = tempfile.mkdtemp(prefix="lo_test_")
    test_txt = os.path.join(temp_dir, "test.txt")
    profile_dir = os.path.join(temp_dir, "profile")

    try:
        with open(test_txt, "w") as f:
            f.write("LibreOffice Conversion Test")
        test_result["steps"].append("Created test file")

        soffice_path = shutil.which("soffice") or "/usr/bin/soffice"
        if not os.path.exists(soffice_path):
            raise Exception(f"soffice not found at {soffice_path}")
        test_result["steps"].append(f"Found soffice at {soffice_path}")

        os.makedirs(profile_dir, exist_ok=True)
        test_result["steps"].append("Created profile directory")

        cmd = [
            soffice_path, "--headless", "--invisible", "--nologo", "--nofirststartwizard",
            "--norestore", f"-env:UserInstallation=file://{profile_dir}",
            "--convert-to", "pdf", "--outdir", temp_dir, test_txt,
        ]
        test_result["steps"].append(f"Running: {' '.join(cmd[:5])}...")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "HOME": profile_dir, "SAL_USE_VCLPLUGIN": "svp"}
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)

        test_result["steps"].append(f"Exit code: {proc.returncode}")
        if stdout:
            test_result["steps"].append(f"stdout: {stdout.decode()[:200]}")
        if stderr:
            test_result["steps"].append(f"stderr: {stderr.decode()[:200]}")

        pdf_path = os.path.join(temp_dir, "test.pdf")
        if os.path.exists(pdf_path):
            pdf_size = os.path.getsize(pdf_path)
            test_result["steps"].append(f"PDF created: {pdf_size} bytes")
            test_result["success"] = True
        else:
            test_result["steps"].append("PDF NOT created!")
            test_result["error"] = "Conversion completed but no PDF output"

    except asyncio.TimeoutError:
        test_result["error"] = "Conversion timed out after 60 seconds"
        test_result["steps"].append("TIMEOUT")
    except Exception as e:
        test_result["error"] = str(e)
        test_result["steps"].append(f"ERROR: {e}")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
        test_result["duration_seconds"] = round(time.time() - start_time, 2)

    return test_result
