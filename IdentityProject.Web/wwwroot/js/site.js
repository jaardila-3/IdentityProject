//#region datepicker
$(function () {
    $("#datepicker").datepicker({
        changeMonth: true,
        changeYear: true,
        yearRange: "1930:2020",
        dateFormat: "dd/mm/yy"
    });
});
//#endregion

//#region datatables
$(document).ready(function () {
    $('#datatables').DataTable(
        {
            language: {
                "decimal": ",",
                "thousands": ".",
                "emptyTable": "No hay datos disponibles",
                "info": "Mostrando registros del _START_ al _END_ de un total de _TOTAL_ registros",
                "infoEmpty": "Mostrando registros del 0 al 0 de un total de 0 registros",
                "infoFiltered": "(filtrado de un total de _MAX_ registros)",
                "zeroRecords": "No se encontraron resultados",
                "infoPostFix": "",
                "lengthMenu": "Mostrar _MENU_ registros",
                "loadingRecords": "Cargando...",
                "sSearch": "Buscar:",
                "oPaginate": {
                    "sFirst": "Primero",
                    "sLast": "Último",
                    "sNext": "Siguiente",
                    "sPrevious": "Anterior"
                },
                "sProcessing": "Cargando..."
            }
        }
    );
});
//#endregion