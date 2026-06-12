#ifndef RECIPE_ENGINE_H
#define RECIPE_ENGINE_H

#include <string>
#include <vector>
#include <map>
#include <QObject>
#include <QDateTime>

// Structure to hold step parameters
struct StepParams {
    std::string key;
    std::string iv;
    int param1 = 0;
    int param2 = 0;
    bool encrypt = true;
    std::map<std::string, std::string> custom_params;
};

// Represents a single active operation in a workflow chain
struct RecipeStep {
    std::string operation_name;
    bool enabled = true;
    StepParams params;
    
    // Intermediate results for debugging
    std::string intermediate_output;
    bool has_error = false;
    std::string error_message;
    double execution_time_ms = 0.0;
};

// Metrics collected after executing a recipe
struct RecipeMetrics {
    double total_time_ms = 0.0;
    double throughput_mbs = 0.0;
    size_t memory_used_bytes = 0;
    QDateTime timestamp;
};

class RecipeEngine : public QObject {
    Q_OBJECT
public:
    RecipeEngine(QObject *parent = nullptr);
    ~RecipeEngine() = default;

    // Manage steps
    void addStep(const std::string &name);
    void removeStep(int index);
    void clearSteps();
    void swapSteps(int index1, int index2);
    void setStepEnabled(int index, bool enabled);
    const std::vector<RecipeStep>& getSteps() const { return m_steps; }
    std::vector<RecipeStep>& getSteps() { return m_steps; }

    // Execute recipe
    std::string run(const std::string &input, int debug_until_step = -1);
    
    // Macro Scripting Parser
    bool parseMacroScript(const std::string &script, std::string &error_msg);
    std::string exportToJSON() const;
    bool importFromJSON(const std::string &json_str, std::string &error_msg);

    // Get latest execution statistics
    const RecipeMetrics& getLatestMetrics() const { return m_metrics; }

signals:
    void executionFinished(const std::string &final_output, const RecipeMetrics &metrics);
    void stepExecuted(int step_index, bool success, double time_ms);

private:
    std::vector<RecipeStep> m_steps;
    RecipeMetrics m_metrics;

    std::string executeSingleStep(const std::string &input, const RecipeStep &step, bool &success, std::string &error_msg);
};

#endif // RECIPE_ENGINE_H
