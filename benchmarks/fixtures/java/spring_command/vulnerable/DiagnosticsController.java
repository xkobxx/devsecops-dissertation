// Deliberately vulnerable benchmark fixture. Do not deploy.
package benchmark;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
final class DiagnosticsController {
    @GetMapping("/diagnostics")
    Process run(@RequestParam String command) throws Exception {
        return Runtime.getRuntime().exec(command);
    }
}
