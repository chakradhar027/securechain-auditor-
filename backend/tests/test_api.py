import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app

@pytest.mark.asyncio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "SecureChain" in data["app"]

@pytest.mark.asyncio
async def test_upload_and_scan_pipeline():
    sample_sol = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    contract SampleBank {
        mapping(address => uint256) public balances;
        function deposit() external payable { balances[msg.sender] += msg.value; }
        function withdraw() external {
            uint256 b = balances[msg.sender];
            (bool s, ) = msg.sender.call{value: b}("");
            require(s);
            balances[msg.sender] = 0;
        }
    }
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. Upload code
        up_res = await ac.post("/api/v1/upload/code", data={"name": "SampleBank", "source_code": sample_sol})
        assert up_res.status_code == 201
        contract_data = up_res.json()
        contract_id = contract_data["id"]

        # 2. Trigger scan
        scan_res = await ac.post("/api/v1/scanner/start", json={
            "contract_id": contract_id,
            "engines": ["custom", "slither", "foundry"]
        })
        assert scan_res.status_code == 200
        scan_data = scan_res.json()
        assert scan_data["status"] == "COMPLETED"
        assert scan_data["total_vulnerabilities"] > 0
        assert scan_data["risk_level"] in ["CRITICAL", "HIGH"]

        # 3. Check findings list
        find_res = await ac.get(f"/api/v1/findings/?scan_id={scan_data['id']}")
        assert find_res.status_code == 200
        assert len(find_res.json()) > 0

        # 4. Check summary history
        hist_res = await ac.get("/api/v1/history/summary")
        assert hist_res.status_code == 200
        assert hist_res.json()["total_scans"] >= 1
