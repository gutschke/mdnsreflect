import time
from unittest.mock import MagicMock
import mdnsreflect

def make_info(name):
    i = MagicMock()
    i.name = name; i.type = "_ipp._tcp.local."; i.server = "printer.local."
    i.addresses = [b'\x0a\x63\x01\x02']; i.port = 631
    return i

def test_hold_reap_return_expire():
    tgt, src = MagicMock(), MagicMock()
    L = mdnsreflect.ReflectorListener(tgt, src, "target", [], hold_secs=60)
    name = "Printer._ipp._tcp.local."
    info = make_info(name)
    L.reflected_services[name] = info                      # pretend it's reflected

    # 1) source loses it -> HELD, not withdrawn
    L.remove_service(None, info.type, name)
    assert name in L.lost_since, "should be held"
    tgt.unregister_service.assert_not_called()
    assert name in L.reflected_services

    # 2) reap while still absent + within hold -> stays held
    src.get_service_info.return_value = None
    L.reap_lost()
    tgt.unregister_service.assert_not_called()
    assert name in L.reflected_services

    # 3) device answers again on reap -> hold cleared, kept
    src.get_service_info.return_value = info
    L.reap_lost()
    assert name not in L.lost_since, "hold should clear on return"
    tgt.unregister_service.assert_not_called()

    # 4) lose again, age the hold past hold_secs, still absent -> withdrawn
    L.remove_service(None, info.type, name)
    L.lost_since[name] = time.time() - 61
    src.get_service_info.return_value = None
    L.reap_lost()
    tgt.unregister_service.assert_called_once()
    assert name not in L.reflected_services and name not in L.lost_since
    print("PASS test_hold_reap_return_expire")

def test_hold_zero_is_legacy_immediate():
    tgt, src = MagicMock(), MagicMock()
    L = mdnsreflect.ReflectorListener(tgt, src, "target", [], hold_secs=0)
    name = "P._ipp._tcp.local."; info = make_info(name)
    L.reflected_services[name] = info
    L.remove_service(None, info.type, name)
    tgt.unregister_service.assert_called_once()   # immediate withdraw
    assert name not in L.reflected_services
    print("PASS test_hold_zero_is_legacy_immediate")

def test_add_service_clears_hold():
    tgt, src = MagicMock(), MagicMock()
    L = mdnsreflect.ReflectorListener(tgt, src, "target", [], hold_secs=60)
    name = "Q._ipp._tcp.local."; info = make_info(name)
    L.reflected_services[name] = info
    L.remove_service(None, info.type, name)
    assert name in L.lost_since
    # a fresh announcement re-triggers add_service; source resolves, already registered
    src.get_service_info.return_value = info
    tgt.register_service.side_effect = mdnsreflect.ServiceNameAlreadyRegistered
    L.add_service(None, info.type, name)
    assert name not in L.lost_since, "add_service must cancel the hold"
    print("PASS test_add_service_clears_hold")

test_hold_reap_return_expire()
test_hold_zero_is_legacy_immediate()
test_add_service_clears_hold()
print("ALL PASS")
