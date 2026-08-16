// Patched benchmark equivalent with a fixed executable and allowlisted argument.
package benchmark;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
final class DiagnosticsController {
    @GetMapping("/diagnostics")
    Process run(@RequestParam String target) throws Exception {
        if (!target.matches("[a-z0-9.-]{1,64}")) throw new IllegalArgumentException();
        return new ProcessBuilder("/usr/bin/dig", target).start();
    }
}
